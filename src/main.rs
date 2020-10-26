use std::io;
use std::vec::*;
use std::net::TcpStream;
use std::io::prelude::*;
use std::os::unix::io::{AsRawFd};


extern crate ssh2;
extern crate rustop;
extern crate whoami;
extern crate subprocess;
extern crate rpassword;
extern crate filedescriptor;
extern crate task_queue;


fn auth(host: &str, user: &str, sess: &ssh2::Session) -> Result<bool, ssh2::Error> {
    match sess.userauth_agent(&user) {
        Ok(v) => v,
        Err(_) => {
            sess.userauth_password(
                user,
                &rpassword::read_password_from_tty(Some(&format!("{}@{}'s password: ", user, host))).unwrap(),
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


fn run(sess: &ssh2::Session, command: &str) -> Result<i32, ssh2::Error> {
    let mut channel = sess.channel_session()?;
    channel.exec(&command)?;

    sess.set_blocking(false);

    let mut pfd = [filedescriptor::pollfd {
        fd: sess.as_raw_fd(),
        events: filedescriptor::POLLIN,
        revents: 0,
    }];

    let mut stdout_dst = io::stdout();
    let mut stdout_src = channel.stream(0);
    let mut stderr_dst = io::stderr();
    let mut stderr_src = channel.stderr();

    loop {
        filedescriptor::poll(&mut pfd, None).ok();

        proxy_io(&mut stdout_src, &mut stdout_dst);
        proxy_io(&mut stderr_src, &mut stderr_dst);

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
    println!("Starting on {}", task.host);
    let sess = connect(&task.host, task.port).unwrap();
    assert!(auth(&task.host, &task.user, &sess).unwrap());
    run(&sess, &task.command).unwrap();
    println!("Finished on {}", task.host);
    return Ok(());
}


#[derive(Debug, Clone)]
struct Task {
    user: String,
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
        opt num_threads:usize=10,
            desc:"Number of concurrent threads to use for parallel execution";
        opt user:String=whoami::username(),
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
                user: opts.user.clone(),
                port: opts.port,
                host: host.clone(),
                command: opts.command.clone(),
            };
        },
    ).collect();

    if opts.parallel {
        let mut queue = task_queue::TaskQueue::with_threads(1, opts.num_threads);
        for task in tasks {
            queue.enqueue(move || {
                run_task(task.clone()).unwrap(); 
            }).unwrap();
        }
        queue.stop_wait();
    } else {
        for task in tasks {
            run_task(task).unwrap();
        }
    }
}
