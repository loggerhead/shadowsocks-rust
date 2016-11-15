use mio::tcp::{TcpListener, TcpStream};
use mio::{Token, EventSet, EventLoop, PollOpt};

use mode::ServerChooser;
use config::Config;
use collections::Holder;
use asyncdns::DnsResolver;
use util::{RcCell, new_rc_cell};
use error::{Result, SocketError, Error as UnionError};
use super::{init_relay, TcpProcessor, MyHandler, Relay};
use super::tcp_processor::LOCAL;

pub struct TcpRelay {
    token: Token,
    conf: Config,
    listener: TcpListener,
    dns_token: Token,
    dns_resolver: RcCell<DnsResolver>,
    server_chooser: RcCell<ServerChooser>,
    processors: Holder<RcCell<TcpProcessor>>,
}

impl TcpRelay {
    pub fn new(conf: Config) -> Result<TcpRelay> {
        init_relay(conf, |conf,
                    token,
                    dns_token,
                    dns_resolver,
                    server_chooser,
                    processors,
                    socket_addr,
                    _prefer_ipv6| {
            let listener =
                TcpListener::bind(&socket_addr).or(Err(SocketError::BindAddrFailed(socket_addr)))?;

            if cfg!(feature = "sslocal") {
                info!("ssclient tcp relay listen on {}", socket_addr);
            } else {
                info!("ssserver tcp relay listen on {}", socket_addr);
            }

            Ok(TcpRelay {
                token: token,
                conf: conf,
                listener: listener,
                dns_token: dns_token,
                dns_resolver: dns_resolver,
                server_chooser: server_chooser,
                processors: processors,
            })
        })
    }

    pub fn run(self) -> Result<()> {
        let mut event_loop = EventLoop::new()?;
        event_loop.register(&self.listener,
                      self.token,
                      EventSet::readable(),
                      PollOpt::edge() | PollOpt::oneshot())
            .or(Err(SocketError::RegisterFailed))?;
        self.dns_resolver
            .borrow_mut()
            .register(&mut event_loop)
            .or(Err(SocketError::RegisterFailed))?;
        let this = new_rc_cell(self);
        event_loop.run(&mut Relay::Tcp(this))?;
        Ok(())
    }

    fn destroy_processor(&mut self, event_loop: &mut EventLoop<Relay>, token: Token) {
        let tokens = self.processors[token].borrow_mut().destroy(event_loop);
        self.processors.remove(tokens.0);
        self.processors.remove(tokens.1);
    }

    fn create_processor(&mut self,
                        event_loop: &mut EventLoop<Relay>,
                        local_token: Token,
                        remote_token: Token,
                        conn: TcpStream)
                        -> Result<()> {
        let p = TcpProcessor::new(local_token,
                                  remote_token,
                                  self.conf.clone(),
                                  conn,
                                  self.dns_resolver.clone(),
                                  self.server_chooser.clone())?;
        let p = new_rc_cell(p);
        self.processors.insert_with(local_token, p.clone());
        self.processors.insert_with(remote_token, p.clone());

        p.borrow_mut().reset_timeout(event_loop);
        self.dns_resolver.borrow_mut().add_caller(p.clone());
        let res = p.borrow_mut().register(event_loop, LOCAL);
        match res {
            Err(e) => {
                self.destroy_processor(event_loop, local_token);
                Err(e)
            }
            res => res,
        }
    }

    fn handle_events(&mut self, event_loop: &mut EventLoop<Relay>, events: EventSet) -> Result<()> {
        event_loop.reregister(&self.listener,
                        self.token,
                        EventSet::readable(),
                        PollOpt::edge() | PollOpt::oneshot())?;
        if events.is_error() {
            error!("events error on tcp relay: {:?}",
                   self.listener.take_socket_error().unwrap_err());
            return err_from!(SocketError::EventError);
        }

        match self.listener.accept()? {
            Some((conn, _addr)) => {
                debug!("create tcp processor for {}", _addr);
                let tokens = (self.processors.alloc_token(), self.processors.alloc_token());
                if let (Some(local_token), Some(remote_token)) = tokens {
                    self.create_processor(event_loop, local_token, remote_token, conn)
                } else {
                    match tokens {
                        (None, None) => {}
                        (Some(t), None) | (None, Some(t)) => {
                            self.processors.remove(t);
                        }
                        (Some(t1), Some(t2)) => {
                            self.processors.remove(t1);
                            self.processors.remove(t2);
                        }
                    }
                    err_from!(SocketError::AllocTokenFailed)
                }
            }
            None => Ok(()),
        }
    }
}

impl MyHandler for TcpRelay {
    fn ready(&mut self, event_loop: &mut EventLoop<Relay>, token: Token, events: EventSet) {
        if token == self.token {
            if let Err(e) = self.handle_events(event_loop, events) {
                error!("tcp relay: {:?}", e);
            }
        } else if token == self.dns_token {
            if let Err(e) = self.dns_resolver.borrow_mut().handle_events(event_loop, events) {
                error!("dns resolver: {:?}", e);
            }
        } else {
            let res = self.processors.get(token).map(|p| {
                p.borrow_mut().fetch_error()?;
                p.borrow_mut().handle_events(event_loop, token, events)
            });
            if let Some(Err(e)) = res {
                match e {
                    UnionError::SocketError(SocketError::ConnectionClosed) => {}
                    _ => {
                        error!("{:?}: {:?}",
                               &self.processors[token].borrow() as &TcpProcessor,
                               e)
                    }
                }
                self.destroy_processor(event_loop, token);
            }
        }
    }

    fn timeout(&mut self, event_loop: &mut EventLoop<Relay>, token: Token) {
        self.processors.get(token).map(|p| {
            debug!("{:?} timed out", p);
        });
        self.destroy_processor(event_loop, token);
    }
}
