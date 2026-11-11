# 赛务邮件附件的邮箱世代资料

此项目维护本地合成来源、协议资料及原始字节工具，用于复查机器人赛事与课程资料。所有名称、数据和地址都不代表真实组织或设备。

`source_lab` 提供资料服务，`sources` 保存业务样本，`workbench.raw_store` 按摘要存取原始字节。HTTP来源的每条路由可依次返回多个响应，最后一个响应会重复；服务仅绑定环回地址。详细数据格式见 [资料约定](docs/source-format.md)。

使用 Python 3.11 或以上版本，无第三方Python依赖。在项目根目录执行：

```sh
python -m unittest discover -s tests -v
python -m compileall -q workbench source_lab tests
python -m workbench.cli inspect sources
```

启动本地HTTP资料服务：

```sh
python -m source_lab.http sources/normal.json --port 8765
```

启动本地IMAP资料服务并对授权邮箱做一轮只读收集（EXAMINE/UID SEARCH/UID FETCH BODY.PEEK[]）：

```sh
python -m source_lab.imap sources/mailbox.json --port 8143
python -m workbench.mailcollect collect --port 8143 --mailbox INBOX --out var/mail
python -m workbench.mailcollect report --out var/mail
python -m workbench.mailcollect replay --out var/mail --identity INBOX/700/2
```

收集端以邮箱标识+UIDVALIDITY+UID为邮件身份，Message-ID仅作元数据；每轮固定UIDNEXT边界，UIDVALIDITY变化开启新世代且旧档案保留。原始邮件按摘要存于 `var/mail/raw/`，附件按身份与部件路径存于 `var/mail/materials/`（inline资源与message/rfc822内嵌附件不重复导入，非法编码与危险文件名旁路），轮次报告写入 `var/mail/reports/`，`replay` 按身份离线重放解析。

容器方式可执行 `docker build -t resource-source .`，随后 `docker run --rm resource-source python -m unittest discover -s tests -v`。服务地址只对本次运行有效，客户端应从配置取得地址。输出资料写入单独目录，原始样本保持只读。
