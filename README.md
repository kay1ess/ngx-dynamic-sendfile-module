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
    dy_send_buffer 2k;
    dy_send_timeout 10s;
    file_suffix ".tmp";
    dy_send_file;  # 这一项必须要配置 否则模块不生效
}
```

运行
-------------------------------------------------
```
./test.sh
curl http://127.0.0.1:8080/send/hello.txt
```
