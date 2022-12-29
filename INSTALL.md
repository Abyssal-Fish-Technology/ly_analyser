#### ly_analyser 分析引擎

​		ly_analyser是流影的威胁行为分析引擎，读取netflow v9格式的数据作为输入，运行各种威胁行为检测模型，产出威胁事件，并留存相关特征数据用于后续取证分析。包括扫描、DGA、DNS隧道、ICMP隧道、服务器外联、 挖矿、各种注入等威胁行为，涵盖机器学习、威胁情报、数据包检测、经验模型四种识别方式。



##  安装部署

```
1. 需求系统环境
	CentOS-7-x86_64-Minimal-2009

2. 安装依赖组件
	yum install net-tools ntpdate -y
	yum install boost -y
	yum install httpd -y
	yum install stunnel -y
	yum install rsync -y
	yum install sysstat -y
	
3. 安装分析引擎
	# 下载主程序部署包 ly_analyser_release.v1.0.0.221226.tar.gz，并解压文件
	tar -xzvf ly_analyser_release.v1.0.0.221226.tar.gz
	
	# 下载所附依赖环境包 ly_analyser_dependence.v1.0.0.221226.tar.gz
	# 解压后置于上述解压缩后生成的目录中
	tar -xzvf ly_analyser_dependence.v1.0.0.221226.tar.gz
	mv ly_analyser_dependence.v1.0.0.221226/*  ly_analyser_release.v1.0.0.221226/

	# 进入程序目录，执行部署脚本
	cd ly_analyser_release.v1.0.0.221226
	./agent_deploy_new.sh

```



## 配置

#### 一、运行环境配置

```
1. 配置环境语言及时区
	export LANG=en_US.UTF-8
	ln -s /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
	ntpdate cn.pool.ntp.org 
	
2. 关闭seliunx，开放本地防⽕墙端口
	#编辑config⽂件
	vi /etc/selinux/config
	#找到配置项
	SELINUX=enforcing
	#修改配置项为
	SELINUX=disabled
	
	#执⾏命令，即时关闭selinux
	setenforce 0 

	#开放本地防⽕墙端口
	systemctl restart firewalld
	firewall-cmd --zone=public --add-port=10081/tcp --permanent
	firewall-cmd --reload

3. 配置httpd
	 编辑文件/etc/httpd/conf.d/agent.conf，写入内容：
	 Listen 10081
	 <VirtualHost *:10081>
	     DocumentRoot /Agent/cmd
	     <Directory "/Agent/cmd">
	         Options ExecCGI
	         SetHandler cgi-script
	         AllowOverride None
	         Order allow,deny
	         Allow from all
	         Require all granted
	     </Directory>
	 </VirtualHost>
	 
	 #重启httpd
	 systemctl restart httpd
```



#### 二、运行配置

``` 
4. 创建定时任务
	vi /var/spool/cron/apache，加入内容：
	*/5 * * * * /Agent/bin/extractor
	 
5. 启动nfcapd接收探针发送的netflow数据
	/Agent/bin/nfcapd -w -D -l /data/flow/3 -p 9995
```



