# 声明:
**该工具长期未更新维护，多数情况下已无法满足使用需求，目前已有多个其他同类型的优秀开源项目。本工具私有版/外部版本均已停止开发。**

# sharp-dumpKey

基于`C#`实现的获取微信数据库密钥的小工具，可配合[`chatViewTool`](https://github.com/Ormicron/chatViewTool)使用。

![poc](https://github.com/Ormicron/Sharp-dumpkey/blob/main/demo1.png)



* 暂时不支持微信多开场景的密钥获取。
* 需微信登录后才可抓取密钥。
* 程序未采用动态获取基址的方式，因此为保证程序可用性，运行时会在线拉取基址。
* 难免存在小版本基址遗漏，欢迎PR-[Address.json](https://github.com/Ormicron/Sharp-dumpkey/blob/main/Address.json)



## 免责声明
**本项目仅允许在授权情况下对数据库进行备份，严禁用于非法目的,否则自行承担所有相关责任。使用该工具则代表默认同意该条款，**
