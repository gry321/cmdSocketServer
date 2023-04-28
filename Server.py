from cmd import Cmd as cmd  # Input Module
import socket  # Main Module
import webbrowser as wb  # Connect Module
#import subprocess as sp
import random  # Port Module
import pickle  # Encryption Module
import sys  # Red String Module
#import threading as td
import os  # Extension Module
import signal  # Listen Ctrl&C Module
import warnings  # Show Warnings Module
import base64  # Encryption Module
import uuid  # UUID Module
import traceback  # Listen Error Module


class info:
    def __init__(self):
        #self.msg = msg
        pass

    def __call__(self, fun):
        def warp(*args, **kw):
            msg = fun(*args, **kw)
            print(msg, file=sys.stderr)
        return warp


class SystemErrorExitException(Exception):
    pass


class a(cmd):
    prompt = "Server code>>>"

    global port
    port = str(random.randint(1, 65535))
    global pwd
    global p

    p = str(uuid.uuid1())
    p = "".join(p.split("-"))
    pwd = base64.b64encode(p.encode()).decode()
    intro = "默认，主机：127.0.0.1，端口：{port}，最大人数：5". format(
        port=port)

    def __init(self):
        #self.host = "127.0.0.1"
        #self.port = 3985
        #self.listen = 5
        super().__init__()
        #print("New server")

    def do_host(self, line):
        if line == "myhost":
            self.host = socket.gethostbyname(socket.gethostname())
        else:
            self.host = line

    def do_encryption(self, line):
        self.encryption = not self.encryption
        print("OK")

    def do_recvNum(self, line):
        try:
            self.recvNum = int(line)
        except ValueError:
            print("请重新输入")

    def do_extension(self, line):
        if line.upper() == "GETMYADDRNAME":
            @info()
            def echo():
                return os.getlogin()
            echo()
        if line.upper() == "ERROREXIT":
            warnings.warn("OK Exit")
            raise SystemErrorExitException
        elif line == "help":
            print("功能：")
            print("\tgetmyaddrname\n\terrorexit")

    def do_port(self, line):
        code = 0
        if line == "random":
            r = ""
            r += str(random.randint(1, 65535))
            r = int(r)
            self.port = r
            code = 1
        if code != 1:
            try:
                self.port = int(line)
            except ValueError:
                print("请重新输入")

    def do_listen(self, line):
        try:
            self.listen = int(line)
        except ValueError:
            print("请重新输入")

    def do_exearg(self, line):
        print("Server 服务器")

    def do_exename(self, line):
        print("文件："+__file__)

    def do_open(self, line):
        # print("这个功能不能用，作者试过")
        if line == "browser":
            wb.open(
                "http://{host}:{port}". format(host=self.host, port=str(self.port)))
        # pass
    """
    def do_spider(self,line):
        self.mode = "spider"
        print("已使用Spider模式")
    """

    def do_get(self, line):
        val = os.popen("ping "+line)
        for x in val:
            print(x)
        val.close()

    def do_cmd(self, line):
        val = os.popen(line)
        stop = True

        def ctrl_c(num, frame):
            global stop
            stop = False
            print("Ctrl+C")
        signal.signal(signal.SIGINT, ctrl_c)
        for x in val:
            if stop != True:
                break
            #print("Stop is :",stop)
            print(x)
        val.close()

    def do_setdir(self, line):
        os.chdir(os.path.expanduser(line))

    def do_getdir(self, line):
        print(os.getcwd())

    def do_ping(self, user):
        try:
            host = socket.gethostbyname(user)
            print(host)
        except socket.gaierror:
            print("不存在这个名字")

    def do_getmyhostIPv4(self, line):
        user = socket.gethostname()
        ip = socket.gethostbyname(user)
        print(ip)

    def do_scan(self, line):
        exe = os.popen("nmap " + line)
        print(exe.read())

    def do_connect(self, line):
        code = line.split(" ")
        try:
            port = int(code[1])
        except:
            print("Port错误")
        else:
            host = code[0]
            a = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                a.connect((host, port))
            except ConnectionRefusedError:
                print("连接错误")
            else:
                while True:
                    msg = input("请输入内容：")
                    if msg == "%exit%":
                        b = input("是代码吗？(y-n)")
                        if b == "y":
                            break
                    if self.encryption:
                        g = pickle.dumps(msg)
                    else:
                        g = bytes(msg, encoding="utf-8")
                    try:
                        a.send(g)
                    except Exception:
                        print("对方已经退出")
                        break
                    try:
                        m = a.recv(self.recvNum)
                    except Exception:
                        print("对方已经退出")
                    try:
                        m = pickle.loads(m)

                        @info()
                        def echo():
                            return "对方用了Pickle"
                        echo()
                    except Exception:
                        m = str(m, encoding="utf-8")
                    print("对方："+m)
                a.close()

    """      
    def do_headers(self,line):
        if self.mode == "spider":
            g = line.split(" ")
            if g[0] == "name":
                self.headers["Name"] = g[1]
            print("设置完毕")    
        else:
            print("请使用Spider模式")  
    def do_status(self,line):
        if self.mode == "spider":
            try:
                stat = int(line)
                self.status = stat
                print("设置完毕")
            except ValueError:
                print("请重新输入")  
        else:
            print("请使用Spider模式")         
    def do_code(self,line):
        if self.mode == "spider":
            self.code = line  
        else:
            print("请使用Spider模式")    
    def do_server(self,line):
        self.mode = "Server"
        self.headers["Server"] = ""
        self.headers["Refresh"] = ""
        self.code = "<html></html>"
        self.status = 200
        self.contenttype = "text/html"
        print("已变成普通模式") 
        """
    # Set help

    def help_args(self):
        print("获取当前配置项")

    def help_exearg(self):
        print("程序是干嘛的")

    def help_exit(self):
        print("退出此程序，和quit一样")

    def help_getmyhostname(self):
        print("获取我电脑的名称（不是用户名）")

    def help_ifrun(self):
        print("判断是否能开始服务器")

    def help_open(self):
        print("连接此服务器，模式：browser，列 ：open browser")

    def help_port(self):
        print("设置port，random是随机")

    def help_run(self):
        print("打开此服务器，最主要的")

    def help_encryption(self):
        print("加密数据并发送")

    def help_exename(self):
        print("获取文件路径")

    def help_getmyhostIPv4(self):
        print("获取本机IPv4地址")

    def help_host(self):
        print("设置IPv4地址，myhost是另一种IPv4地址")

    def help_listen(self):
        print("设置连接最大人数，没用")

    def help_ping(self):
        print("获取电脑名称的IPv4地址")

    def help_quit(self):
        print("退出此程序，和exit一样")

    def help_recvNum(self):
        print("接收的字节数，不建议修改")

    def help_extension(self):
        print("其他扩展，所有功能：extension help")

    def help_scan(self):
        print("扫描端口")

    def help_cmd(self):
        print("使用cmd")

    def help_connect(self):
        print("连接服务器")

    def help_get(self):
        print("cmd的ping")

    def help_setdir(self):
        print("设置用cmd的使用路径")

    def help_getdir(self):
        print("输出使用cmd的路径")
    # Other Help

    def help_this(self):
        @info()
        def echo():
            return "Use python socket module create server"
        echo()

    def do_getmyhostname(self, line):
        print(socket.gethostname())

    def do_run(self, line):
        global is_connect_exit
        is_connect_exit = True

        def process():
            error = 0
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
                try:
                    server.bind((self.host, self.port))
                except OSError:
                    print("有可能输入主机错误")
                    error = 1
                    is_connect_exit = True
                except OverflowError:
                    print("端口只支持0~65535")
                    error = 1
                    is_connect_exit = True
                if not error:
                    server.listen(self.listen)
                    print("服务器初始化完毕 主机:{host} 端口:{port} 最大人数:{listen}". format(
                        host=self.host, port=self.port, listen=self.listen))
                    global conn
                    conn, addr = server.accept()
                    print("有人来到服务器，连接主机：%s，连接端口：%s" % addr)
                    _exit = input("是否退出连接？(y-n)：\n")
                    if _exit == "y":
                        _exit = True
                        conn.close()
                        is_connect_exit = True
                    else:
                        _exit = False
                    if not _exit:
                        is_connect_exit = False
                        while True:
                            try:
                                data = conn.recv(self.recvNum)
                            except Exception:
                                print("他退出了")
                                is_connect_exit = True
                                break
                            try:
                                pkl = False
                                data = pickle.loads(data)
                                pkl = True
                            except Exception:
                                data = str(data, encoding="utf-8")
                            if data == "":
                                @info()
                                def echo_1():
                                    return ""
                            print("对方："+data)
                            if pkl:
                                @info()
                                def echo():
                                    return "对方用了pickle"
                                echo()
                            if data == "" and pkl == False:
                                m = input("可能他已经退出，是否退出？(y-n)")
                                if m == "y":
                                    print("已经退出")
                                    is_connect_exit = True
                                    break
                            if data.upper() == "$EXIT":
                                code = 1
                                t = input("是否退出？(y-n)：\n")
                                if t == "y":
                                    print("因为对方输入EXIT，已退出")
                                    is_connect_exit = True
                                    break
                            elif data.upper() == "$HOST":
                                code = 1
                                t = input("是否让他查看电脑IP？%s(y-n)：\n" %
                                          socket.gethostbyname(socket.gethostname()))
                                if t.upper() == "Y":
                                    conn.send(bytes(socket.gethostbyname(
                                        socket.gethostname()), encoding="utf-8"))
                                else:
                                    code = 0
                            elif data.upper() == "$HOSTNAME":
                                code = 1
                                t = input("是否让他查看电脑名称？%s(y-n)：\n" %
                                          socket.gethostname())
                                if t.upper() == "Y":
                                    conn.send(
                                        bytes(socket.gethostname(), encoding="utf-8"))
                                else:
                                    code = 0
                            elif data.upper() == "$ADDRNAME":
                                code = 1
                                t = input("是否让他查看用户名？%s(y-n)：\n" %
                                          os.getlogin())
                                if t.upper() == "Y":
                                    conn.send(
                                        bytes(os.getlogin(), encoding="utf-8"))
                                else:
                                    code = 0
                            else:
                                code = 0
                            if not code:
                                msg = input("请你输入内容：")
                                if msg.upper() == "$EXIT THE FILE":
                                    r = input("是退出还是信息？(1-2)：")
                                    if r == "1":
                                        print("已退出了")
                                        is_connect_exit = True
                                        break
                                if self.encryption:
                                    msg = pickle.dumps(msg)
                                else:
                                    msg = bytes(msg, encoding="utf-8")
                                try:
                                    conn.send(msg)
                                except ConnectionAbortedError:
                                    print("对方已退出")
                                    is_connect_exit = True
                        conn.close()
        #td.Thread(target=process,name="Server process 1",args=()).start()
        process()
        """
    def do_contenttype(self,line):
        if self.mode == "spider":
            self.contenttype = "text/"+line
            print("设置完毕")  
        else:  
            print("请使用Spider模式")            
    def do_spiderrun(self,line):
        if self.mode == "spider":
            error = 0
            with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as server:
                try:
                    server.bind((self.host,self.port))  
                except OSError:
                    print("有可能输入主机错误")      
                    error = 1
                except OverflowError:
                    print("端口只支持0~65535")
                    error = 1
                else:        
                    if not error:
                        server.listen(self.listen)
                        print("服务器初始化完毕 主机:{host} 端口:{port} 最大人数:{listen}". format(host=self.host,port=self.port,listen=self.listen))
                        conn,addr = server.accept()
                        print("有人来到服务器，连接主机：%s，连接端口：%s" % addr)
                        while True:
                            try:
                                data = conn.recv(1024)
                            except Exception:
                                print("他退出了")
                                break 
                            data = conn.recv(1024)
                            data = str(data,encoding="utf-8")
                            print("对方："+data)
                            y = input("是否给对方爬虫？(y-n)：\n")
                            if y == "y":
                                res_start = "HTTP/1.1 {status}OK\r\n". format(status=str(self.status))
                                res_headers = "Server: {server}\r\n" \
                                    "Content-Type: {contenttype}". format(server=self.headers["Server"],contenttype=self.contenttype)
                                res_body = self.code
                                res = res_start + res_headers + "\r\n" + res_body
                                conn.send(bytes(res,encoding="utf-8"))   
                        conn.close()             
        else:
            print("请使用Spider模式")   
            """

    def do_ifrun(self, line):
        try:
            a = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            a.bind((self.host, self.port))
            a.listen(self.listen)
            a.close()
            print("能开始")
        except Exception:
            print("不能开始")

    # 退出代码
    def do_exit(self, line):
        print("退出")
        return True

    def do_quit(self, line):
        print("退出")
        return True

    def do_args(self, line):
        print("主机："+self.host+"，修改代码：host")
        print("端口："+str(self.port)+"，修改代码：port")
        print("最大人数："+str(self.listen)+"，修改代码：listen")
        print("加密："+str(self.encryption)+"，修改代码：encryption")
        print("接收字节数："+str(self.recvNum)+"，修改代码：recvNum")

    def default(self, line):
        @info()
        def echo():
            return "没有这个代码，"+line
        echo()
        # print("没有这个代码，"+line)

    def ii(self):
        self.host = "127.0.0.1"
        self.port = int(port)
        self.listen = 5
        self.encryption = False  # 加密
        self.recvNum = 1024
        self.p = p
        #self.p = p
        self.pwd = pwd
        self.ispwd = False
        # Spider Config
        self.mode = "Server"
        self.headers = {"Server": ""}
        self.status = 200
        self.code = "<html></html>"
        self.contenttype = "text/html"


if __name__ == "__main__":
    code = a()
    code.ii()
    try:
        code.cmdloop()
    except KeyboardInterrupt:
        print("\n")
        print("Bye bye!")
        sys.exit(0)
