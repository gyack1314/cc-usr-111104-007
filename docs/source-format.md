# 合成邮箱

启动 `python -m source_lab.imap sources/mailbox.json --port 8143`。仅环回接口，demo用户名密码只是合成协议占位，不需要真实凭据。EXAMINE与UID FETCH BODY.PEEK[]只读，来源对不支持命令返回BAD。修改配置文件或指定migrated.json可切换世代；下一条命令读取当前配置。UID SEARCH来源可返回全部UID，客户端负责按固定UIDNEXT过滤。FETCH顺序反转且夹杂EXISTS，literal长度按实际RFC822字节。

mail-a有attachment和inline，mail-b的message/rfc822附件应保留为整体，mail-bad有损坏base64。文件名参数遵循RFC2231，续段必须从零连续，重复段非法，不能同时存在相冲突的普通名和扩展名。仅接受base64、quoted-printable、7bit、8bit、binary编码；对base64与quoted-printable进行严格合法性检查，原始邮件仍可留存。部件路径用从1开始的MIME子部件序号，根叶部件为1。Message-ID允许重复。来源服务没有附件解码或本地进度。
