ngx_http_dynamic_sendfile_module 动态发送文件
===============================================

作用
-----------------------------------------------
> 通过使用http1.1 chunked encode transfer 技术 发送动态变化的文件


编译
-----------------------------------------------
```
cd nginx-1.x.x
./auto/configure --add-module=../ngx_http_dynamic_sendfile_module
make
make install
```


配置
------------------------------------------------
```
location /send/ {
    alias /tmp/test/;
    dy_send_interval 1s;
    dy_send_timeout 10s;
    file_suffix ".tmp";
    dy_send_file;  # 这一项必须要配置 否则模块不生效
}
```

Demo
-------------------------------------------------
```
# 向/tmp/test/hello.txt 每隔1s写入一行内容 默认写20行
./test.sh
curl http://127.0.0.1:8080/send/hello.txt
```

性能
-------------------------------------------------
+ 测试环境: Intel Corei7 6核 内存16G
+ nginx配置:
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

+ 请求纯静态文件 
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


+ 请求动态变化的文件
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

> 注意: wrk chunked压测支持度不够 只能做参考 待找到合适压测工具再更新压测结果