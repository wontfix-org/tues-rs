use std::io;
use std::vec::*;
use std::boxed::*;
use std::net::TcpStream;
use std::io::prelude::*;
use std::os::unix::io::{AsRawFd};


extern crate ssh2;
extern crate rustop;
extern crate whoami;
extern crate subprocess;
extern crate rpassword;
extern crate filedescriptor;
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


fn proxy_io(src: &mut ssh2::Stream, dst: &mut dyn io::Write) {
    let mut buf = [0u8; 1024];
    match src.read(&mut buf) {
        Ok(size) => {
            if size == 0 {
                return;
            } else {
                dst.write_all(&buf[..size]).unwrap();
            }
        }
        Err(_) => return,
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
    // \n we saw here.
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


fn run(sess: &ssh2::Session, command: &str, mut stdout: &mut dyn io::Write, mut stderr: &mut dyn io::Write) -> Result<i32, ssh2::Error> {
    let mut channel = sess.channel_session()?;
    channel.exec(&command)?;

    sess.set_blocking(false);

    let mut pfd = [filedescriptor::pollfd {
        fd: sess.as_raw_fd(),
        events: filedescriptor::POLLIN,
        revents: 0,
    }];

    let mut stdout_src = channel.stream(0);
    let mut stderr_src = channel.stderr();

    loop {
        filedescriptor::poll(&mut pfd, None).ok();

        proxy_io(&mut stdout_src, &mut stdout);
        proxy_io(&mut stderr_src, &mut stderr);

        if channel.eof() {
            break;
        }
    }

    sess.set_blocking(true);
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


fn run_task(task: Task) -> Result<(), ssh2::Error> {
    let prefix = String::from(format!("[{}]: ", task.host));
    let mut stdout = PrefixWriter::new(Box::new(io::stdout()), &prefix);
    let mut stderr = PrefixWriter::new(Box::new(io::stderr()), &prefix);
    let sess = connect(&task.host, task.port).unwrap();
    assert!(auth(&task.host, &task.login_user, &sess).unwrap());
    run(&sess, &task.command, &mut stdout, &mut stderr).unwrap();
    return Ok(());
}


#[derive(Debug, Clone)]
struct Task {
    login_user: String,
    port: u32,
    host: String,
    command: String,
}


fn run_provider(provider: &str, args: Vec<String>) -> Result<Vec<String>, subprocess::PopenError> {
    let mut argv = args.clone();
    let provider_exe = format!("tues-provider-{}", provider);
    argv.insert(0, provider_exe);

    let mut p = subprocess::Popen::create(
        &argv,
        subprocess::PopenConfig {
            stdout: subprocess::Redirection::Pipe, ..Default::default()
        }
    )?;

    let (out, _err) = p.communicate(None)?;

    if let Some(exit_status) = p.poll() {
        println!("Exited with {:?}", exit_status);
    } else {
        p.terminate()?;
    }
    return Ok(
        match out {
            Some(val) => val.trim_end().split('\n').map(|x| { String::from(x.trim_end()) }).collect(),
            None => vec![],
        }
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
                login_user: opts.login_user.clone(),
                port: opts.port,
                host: host.clone(),
                command: opts.command.clone(),
            };
        },
    ).collect();

    if opts.parallel {
        let mut pool = scoped_threadpool::Pool::new(opts.num_threads);
        pool.scoped(|scope| {
            for task in tasks {
                scope.execute(move || {
                    run_task(task.clone()).unwrap(); 
                });
            }

        });
    } else {
        for task in tasks {
            run_task(task).unwrap();
        }
    }
}
