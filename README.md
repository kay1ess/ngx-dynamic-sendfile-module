ngx_http_dynamic_sendfile_module | [简体中文](README_CN.md)
===============================================

Introduction
-----------------------------------------------
> http1.1 chunked encode transfer to send file it's size is not regular


How to Compile
-----------------------------------------------
```
cd nginx-1.x.x
./auto/configure --add-module=../ngx_http_dynamic_sendfile_module
make
make install
```


Nginx Configuration
------------------------------------------------
```
location /send/ {
    alias /tmp/test/;
    dy_send_interval 1s;
    dy_send_timeout 10s;
    file_suffix ".tmp";
    dy_send_file;  # Need it
}
```

Example
-------------------------------------------------
```
# write some text to file(/tmp/test/hello.txt). Write a line of content every 1s, write 20 lines by default
./test.sh
curl http://127.0.0.1:8080/send/hello.txt
```

Benchmark
-------------------------------------------------
+ Test hardware environment: Intel Corei7 6core 16G RAM
+ nginx.conf:
```
#user  nobody;
worker_processes  auto;

error_log  logs/error.log info;
events {
    worker_connections 1024;
}

http {
    include       mime.types;
    default_type  application/octet-stream;

    sendfile        on;
    tcp_nopush     on;

    keepalive_timeout  65;

    server {
        listen       8080;
        server_name  localhost;

        location /send/ {
            alias /tmp/test/;
            dy_send_interval 1s;
            dy_send_timeout 10s;
            dy_send_file;
        }
    }
}
```

+ Request static files:
```
 wrk -d40s --timeout 60s http://127.0.0.1:8080/send/hello.txt
Running 40s test @ http://127.0.0.1:8080/send/hello.txt
  2 threads and 10 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    85.25ms  168.93ms   1.43s    87.13%
    Req/Sec   245.47     86.03   550.00     70.40%
  18938 requests in 40.10s, 9.91MB read
Requests/sec:    472.30
Transfer/sec:    253.20KB
```


+ Request dynamic files:
./test.sh 20

```
wrk -d40s --timeout 60s http://127.0.0.1:8080/send/hello.txt
Running 40s test @ http://127.0.0.1:8080/send/hello.txt
  2 threads and 10 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     2.80s     5.20s   19.19s    83.21%
    Req/Sec   256.23    124.20   643.00     70.13%
  10015 requests in 40.04s, 5.24MB read
Requests/sec:    250.13
Transfer/sec:    134.10KB
```

> Note: wrk chunked benchmark is not very accurate, only as reference.
