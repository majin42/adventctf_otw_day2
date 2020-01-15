use byteorder::{ByteOrder, LittleEndian};
use log::{info};
use std::error::Error;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::rc::Rc;

pub struct StreamWrapper {
    stream: TcpStream,
    read_offset: usize,
    write_offset: usize,
    cipher_key: Rc<Vec<u8>>,
    secret_key: Rc<Vec<u8>>,
    buffer: [u8; 2048],
    write_hooks: Vec<Box<dyn Fn(Vec<u8>) -> Vec<u8>>>,
}

impl StreamWrapper {
    fn new(
        stream: TcpStream,
        cipher_key: Rc<Vec<u8>>,
        secret_key: Rc<Vec<u8>>,
    ) -> Result<StreamWrapper, Box<dyn Error>> {
        Ok(StreamWrapper {
            stream,
            read_offset: 0,
            write_offset: 0,
            cipher_key,
            secret_key,
            buffer: [0 as u8; 2048],
            write_hooks: Vec::new(),
        })
    }

    fn read(&mut self) -> Result<Vec<u8>, Box<dyn Error>> {
        match self.stream.read(&mut self.buffer) {
            Ok(size) => {
                if size == 0 {
                    return Err("read 0: the connection has been closed".into());
                }

                let ret = self.xor(&self.buffer[..size], self.read_offset);
                self.read_offset += size;
                return Ok(ret);
            }
            Err(e) => {
                return Err(e.into());
            }
        }
    }

    fn write(&mut self, msg: Vec<u8>) -> Result<(), Box<dyn Error>> {
        let mut ret = msg;
        for hook in self.write_hooks.iter() {
            ret = hook(ret);
        }

        ret = self.xor(&ret, self.write_offset);
        self.stream.write_all(&ret)?;
        self.write_offset += ret.len();
        Ok(())
    }

    pub fn send_message<T: protobuf::Message>(
        &mut self,
        msg: &T,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let msg_bytes = msg.write_to_bytes()?;
        let msg_len = msg_bytes.len();
        let mut buf = vec![0; 2];
        LittleEndian::write_u16(&mut buf, msg_len as u16);

        // first write length
        // then write message content
        self.write(buf)?;
        self.write(msg_bytes)?;

        // read the two replies but return only
        // the second one, we only care for the content
        self.read()?;
        let ret = self.read()?;

        Ok(ret)
    }

    fn xor(&self, msg: &[u8], offset: usize) -> Vec<u8> {
        let mut clone_msg: Vec<u8> = Vec::new();
        clone_msg.extend(msg);

        for (i, x) in &mut clone_msg.iter_mut().enumerate() {
            let tmp = i + offset;
            // I don't know if this key rotates or if it's a cipher stream since
            // I couldn't find any repetitions after generating multiple kilobytes
            // of cipher_key.
            // However we make it rotate here so that it does not go out of
            // bounds.
            *x = *x ^ self.cipher_key[tmp % self.cipher_key.len()];

            // this key rotates
            *x = *x ^ self.secret_key[tmp % self.secret_key.len()];
        }

        clone_msg
    }

    pub fn hook_write<U>(&mut self, hook: U) -> ()
    where
        U: Fn(Vec<u8>) -> Vec<u8> + 'static,
    {
        self.write_hooks.push(Box::new(hook));
        println!("{:?}", self.write_hooks.len());
    }

}

pub struct MitmClient {
    pub server: StreamWrapper,
    pub client: StreamWrapper,
    _secret_key: Rc<Vec<u8>>,
    _cipher_key: Rc<Vec<u8>>,
}

impl MitmClient {
    pub fn new(
        srv_host: &str,
        client_host: &str,
        cipher_key: &[u8],
    ) -> Result<MitmClient, Box<dyn Error>> {
        let mut srv_stream = TcpStream::connect(srv_host)?;
        info!("connected to server: {}", srv_host);
        let mut client_stream = TcpStream::connect(client_host)?;
        info!("connected to client: {}", client_host);

        info!("reading server provided key");
        let mut secret_key = vec![0; 16];
        let size = srv_stream.read(&mut secret_key)?;
        println!("size: {}", size);

        info!("sending secret_key to client");
        client_stream.write_all(&secret_key)?;

        info!("reading client connection id");
        let mut connection_id = vec![0; 2048];
        let size = client_stream.read(&mut connection_id)?;
        println!("size: {}", size);
        let id_response = std::str::from_utf8(&connection_id)?;
        println!("{}", id_response);

        let cipher_key = cipher_key.to_vec();
        let rc_secret_key: Rc<Vec<u8>> = Rc::new(secret_key);
        let rc_cipher_key: Rc<Vec<u8>> = Rc::new(cipher_key);

        // create wrappers
        let srv = StreamWrapper::new(
            srv_stream,
            Rc::clone(&rc_cipher_key),
            Rc::clone(&rc_secret_key),
        )?;

        let client = StreamWrapper::new(
            client_stream,
            Rc::clone(&rc_cipher_key),
            Rc::clone(&rc_secret_key),
        )?;

        Ok(MitmClient {
            server: srv,
            client: client,
            _cipher_key: rc_cipher_key,
            _secret_key: rc_secret_key,
        })
    }

    /// launches the man in the middle session.
    ///
    /// Except for the first 16 bytes sent by the server upon initializing the
    /// connection, all communications follow this pattern:
    ///
    /// the client sends a command to the server
    /// [client] --- size of the next message ---> [server]
    /// [client] ---     command message      ---> [server]
    ///
    /// and the server responds
    /// [client] <--- size of the next message --- [server]
    /// [client] <---    response message      --- [server]
    pub fn run(&mut self) -> Result<(), Box<dyn Error>> {
        loop {
            let res = self.client.read()?;
            self.server.write(res)?;
            let res = self.client.read()?;
            self.server.write(res)?;

            let res = self.server.read()?;
            self.client.write(res)?;
            let res = self.server.read()?;
            self.client.write(res)?;
        }
    }
}

pub mod protos;
