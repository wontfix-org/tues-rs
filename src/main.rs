use std::io;
use std::str;
use std::vec::*;
use std::boxed::*;
use std::net::TcpStream;
use std::io::prelude::*;
use std::sync::{Arc,Mutex};
use std::os::unix::io::{AsRawFd};
use std::process::Command;

extern crate ssh2;
extern crate rustop;
extern crate whoami;
extern crate rpassword;
extern crate filedescriptor;
extern crate crossterm_cursor;
extern crate scoped_threadpool;


fn auth(host: &str, login_user: &str, sess: &ssh2::Session) -> Result<bool, ssh2::Error> {
    match sess.userauth_agent(&login_user) {
        Ok(v) => v,
        Err(_) => {
            sess.userauth_password(
                login_user,
                &rpassword::read_password_from_tty(Some(&format!("{}@{}'s password: ", login_user, host))).unwrap(),
            )?;
        },
    }

    return Ok(sess.authenticated());
}


fn proxy_io(src: &mut ssh2::Stream, dst: &mut dyn io::Write, mut buf: &mut [u8]) -> Result<usize, io::Error> {
    buf.iter_mut().for_each(|m| *m = 0);
    match src.read(&mut buf) {
        Ok(size) => {
            if size != 0 {
                dst.write_all(&buf[..size])?;
            }
            return Ok(size);
        }
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(0),
        Err(e) => return Err(e),
    }
}


struct PrefixWriter<'a> {
    base: Box<dyn io::Write>,
    prefix: &'a str,
    // On the first write, we need to add a prefix and remember we did...
    initially_prefixed: bool,
    // We add a prefix on every new line, so *after* a \n, but we can't
    // add it until we see another byte if we don't want to create
    // a trailing line with only a prefix. But we might only see the
    // \n in this call to `write`, so we need to keep track of the
    // fact that we still need to write a prefix if we do another read
    do_prefix: bool,
}


impl<'a> io::Write for PrefixWriter<'a> {

    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        let mut size: usize = 0;
        if ! self.initially_prefixed {
            self.base.write(self.prefix.as_bytes())?;
            self.initially_prefixed = true;
        }

        for c in buf {
            if self.do_prefix {
                self.base.write(self.prefix.as_bytes())?;
                self.do_prefix = false;
            }
            if *c == '\n' as u8 {
                self.do_prefix = true;
            }
            size += self.base.write(&[*c])?;
        }
        return Ok(size);
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        return self.base.flush();
    }
}


impl<'a> PrefixWriter<'a> {
    fn new(base: Box<dyn io::Write>, prefix: &str) -> PrefixWriter {
        PrefixWriter {
            base: base,
            prefix: prefix,
            initially_prefixed: false,
            do_prefix: false,
        }
    }
}


trait ProxyIO {
    fn proxy(&self, session: &ssh2::Session, channel: &mut ssh2::Channel) -> Result<(), ssh2::Error>;
}


struct TerminalIOProxy<'a> {
    prefix: &'a str,
    errprefix: &'a str,
    pattern: &'a str,
    password: Arc<Mutex<Option<String>>>,
}


fn buf_endswith(buf: &[u8], len: usize, s: &str) -> bool {
    if len < s.len() {
        return false;
    }
    if &buf[len - s.len() .. len] == s.as_bytes() {
        return true;
    }
    return false

}

impl<'a> ProxyIO for TerminalIOProxy<'a> {

    fn proxy(&self, session: &ssh2::Session, mut channel: &mut ssh2::Channel) -> Result<(), ssh2::Error> {
        let mut buf = [0u8; 1024];
        let mut bytes_read: usize;
        let mut attempts = 0;

        session.set_blocking(false);
        let mut pfd = [filedescriptor::pollfd {
            fd: session.as_raw_fd(),
            events: filedescriptor::POLLIN,
            revents: 0,
        }];

        let mut stdout_src = channel.stream(0);
        let mut stderr_src = channel.stderr();
        let mut stdout = PrefixWriter::new(Box::new(io::stdout()), self.prefix);
        let mut stderr = PrefixWriter::new(Box::new(io::stderr()), self.errprefix);

        loop {
            filedescriptor::poll(&mut pfd, None).ok();

            proxy_io(&mut stdout_src, &mut stdout, &mut buf).unwrap();
            bytes_read = proxy_io(&mut stderr_src, &mut stderr, &mut buf).unwrap();

            if buf_endswith(&buf, bytes_read, &self.pattern) {
                self.handle_password_prompt(&mut channel, attempts > 0).unwrap();
                attempts += 1;
                stderr.write(b"\n").unwrap();
            }


            if channel.eof() {
                break;
            }
        }

        session.set_blocking(true);
        return Ok(());
    }
}


impl<'a> TerminalIOProxy<'a> {
    fn new(prefix: &'a str, errprefix: &'a str, pattern: &'a str, password: Arc<Mutex<Option<String>>>) -> TerminalIOProxy<'a> {
        return TerminalIOProxy { prefix: &prefix, errprefix: &errprefix, pattern: &pattern, password: password };
    }

    fn handle_password_prompt(&self, channel: &mut ssh2::Channel, reset: bool) -> Result<(), ssh2::Error> {
        let mut pwguard = self.password.lock().unwrap(); 
        let mut pwoption = pwguard.clone();

        if reset || pwoption.is_none() {
            let cursor = crossterm_cursor::TerminalCursor::new();
            cursor.save_position().unwrap();
            *pwguard = Some(rpassword::read_password_from_tty(Some("")).unwrap());
            pwoption = pwguard.clone();
            cursor.restore_position().unwrap();
        }

        if pwoption.is_some() {
            channel.write(pwoption.unwrap().as_bytes()).unwrap();
            channel.write(b"\n").unwrap();
        }
        return Ok(());
    }
}


fn run(sess: &ssh2::Session, command: &str, proxy: &dyn ProxyIO) -> Result<i32, ssh2::Error> {
    let mut channel = sess.channel_session()?;
    channel.exec(&command)?;
    proxy.proxy(&sess, &mut channel).unwrap();
    channel.wait_close()?;
    return Ok(channel.exit_status()?);
}


fn connect(host: &str, port: u32) -> Result<ssh2::Session, ssh2::Error> {
    let tcp = TcpStream::connect(format!("{}:{}", host, port)).unwrap();
    let mut sess = ssh2::Session::new().unwrap();
    sess.set_tcp_stream(tcp);
    sess.handshake().unwrap();
    return Ok(sess);
}


fn run_task(task: Task, password: Arc<Mutex<Option<String>>>) -> Result<(), ssh2::Error> {
    let prefix = String::from(format!("[{}/stdout]: ", task.host));
    let errprefix = String::from(format!("[{}/stderr]: ", task.host));
    let prompt = "sudo password: ";
    let proxy = TerminalIOProxy::new(&prefix, &errprefix, &prompt, password);
    let sess = connect(&task.host, task.port).unwrap();
    auth(&task.host, &task.login_user, &sess).unwrap();
    if let Some(user) = &task.user {
        let cmd = format!("sudo -S -u '{}' -p '{}' '{}'", &user, &prompt, &task.command);
        run(&sess, &cmd, &proxy).unwrap();
    } else {
        run(&sess, &task.command, &proxy).unwrap();
    }
    return Ok(());
}


#[derive(Debug, Clone)]
struct Task<'a> {
    login_user: &'a str,
    user: Option<&'a str>,
    port: u32,
    host: &'a str,
    command: &'a str,
}


fn run_provider(provider: &str, args: Vec<String>) -> Result<Vec<String>, subprocess::PopenError> {
    let provider_exe = format!("tues-provider-{}", provider);

    let output = Command::new(provider_exe)
        .args(args)
        .output()?;

    return Ok(
        str::from_utf8(&output.stdout)
            .unwrap()
            .trim_end()
            .split('\n')
            .map(|x| { String::from(x.trim_end()) })
            .collect(),
    );
}


fn main() {
    let (opts, rest) = rustop::opts! {
        synopsis "TUES!";
        opt parallel:bool, desc:"Run multiple commands in parallel";
        opt num_threads:u32=10,
            desc:"Number of concurrent threads to use for parallel execution";
        opt login_user:String=whoami::username(),
            desc:"Default username to connect with";
        opt user:Option<String>,
            desc:"Username to run commands as";
        opt port:u32=22,
            desc:"Default port to connect to";
        param command:String,
            desc:"Command to execute on each host";
        param provider:String,
            desc:"Provider name to use for host lookup";
        param provider_args:Vec<String>,
            desc:"Arguments to pass to the provider";

    }.parse_or_exit();

    let mut provider_args = opts.provider_args.clone();
    provider_args.extend_from_slice(&rest);

    let hosts = run_provider(&opts.provider, provider_args).unwrap();
    let tasks: Vec<Task> = hosts.iter().map(
        |host| -> Task {
            return Task {
                login_user: &opts.login_user,
                user: match &opts.user {
                    Some(val) => Some(&val),
                    None => None,
                },
                port: opts.port,
                host: &host,
                command: &opts.command,
            };
        },
    ).collect();
    let password: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

    if opts.parallel {
        let mut pool = scoped_threadpool::Pool::new(opts.num_threads);
        pool.scoped(|scope| {
            for task in tasks {
                let password = Arc::clone(&password);
                scope.execute(move || {
                    run_task(task.clone(), password).unwrap(); 
                });
            }

        });
    } else {
        for task in tasks {
            run_task(task, Arc::clone(&password)).unwrap();
        }
    }
}
