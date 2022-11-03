# HRBNU_CampusNetwork
哈尔滨师范大学校园网深澜python认证 联通电信移动认证

哈尔滨师范大学 校园网 python认证 可用于windows,linux,openwrt上对校园网进行自动认证  
  
linux and openwrt使用教程
```
#先更新opkg列表
opkg update
#安装python
opkg install python3  
opkg install python3-pip  
#最后安装模块（缺啥安啥）
pip install requests  
#运行认证程序完成认证
python main.py
#openwrt特殊设置  
#将认证程序重命名为xyw.py，放入/usr文件夹下
#在crontab计划任务中添加
30 6 * * * python /usr/xyw.py > /dev/null
#即可完成每天6:30分自动认证(需要先配置完成以上环境)
```
