## pppoe拨号流程(转载收集)

> **PPPoE**（Point to Point Protocol over Ethernet，基于以太网的点对点协议）的工作流程包含**发现（Discovery）**和**会话（Session）**两个阶段，发现阶段是**无状态**的，目的是获得PPPoE终端（在局端的ADSL设备上）的以太网MAC地址，并建立一个惟一的PPPoE SESSION-ID。发现阶段结束后，就进入标准的PPP会话阶段。

**1.发现阶段（PPPoED：PPPoE Discovery）**

> 1.1 **PADI**（PPPoE Active Discovery **Initiation**）
>
> 主机广播发起分组，分组的目的地址为以太网的广播地址 0xffffffffffff，CODE（代码）字段值为0×09（PADI Code），SESSION-ID（会话ID）字段值为0x0000。PADI分组必须至少包含一个服务名称类型的**标签**（Service Name Tag，字段值为0x0101），向接入集中器提出所要求提供的服务。
>
> 1.2 **PADO**（PPPoE Active Discovery **Offer**）
>
> 接入集中器收到在服务范围内的PADI分组，发送PPPoE有效发现提供包分组，以响应请求。其中CODE字段值为0×07（PADO Code），SESSION-ID字段值仍为0x0000。PADO分组必须包含一个接入集中器名称类型的标签（Access Concentrator Name Tag，字段值为0x0102），以及一个或多个服务名称类型标签，表明可向主机提供的服务种类。PADO和PADI的Host-Uniq Tag值相同。
>
> 1.3 **PADR**（PPPoE Active Discovery **Request**）
>
> 主机在可能收到的多个PADO分组中**选择一个**合适的PADO分组，然后向所选择的接入集中器发送PPPoE有效发现**请求**分组。其中CODE字段为0x19（PADR Code），SESSION_ID字段值仍为0x0000。PADR分组必须包含一个服务名称类型标签，确定向接入集线器（或交换机）请求的服务种类。当主机在指定的时间内没有接收到PADO，它应该重新发送它的PADI分组，并且**加倍等待**时间，这个过程会被重复期望的次数。
>
> 1.4 **PADS**（PPPoE Active Discovery **Session**-confirmation）
>
> 接入集中器收到PADR分组后准备开始PPP会话，它发送一个PPPoE有效发现会话确认PADS分组。其中CODE字段值为0×65（PADS Code），SESSION-ID字段值为接入集中器所产生的一个**惟一的**PPPoE会话标识号码。PADS分组也必须包含一个接入集中器名称类型的标签以确认向主机提供的服务。当主机收到PADS 分组确认后，双方就进入PPP会话阶段。PADS和PADR的Host-Uniq Tag值相同。
>
> ![img](https://img-blog.csdn.net/20130719173836765?watermark/2/text/aHR0cDovL2Jsb2cuY3Nkbi5uZXQvcGh1bnht/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70/gravity/SouthEast)
>
> 图1 PPPoE的协商流程

**2.会话阶段（PPPoES：PPPoE Session）**

> PPP会话的建立，需要两端的设备都发送LCP数据包来配置和测试数据通信链路。
>
> 用户主机与接入集中器根据在发现阶段所协商的PPP会话连接参数进行PPP会话。一旦PPPoE会话开始，PPP数据就可以以任何其他的PPP封装形式发送。所有的以太网帧都是**单播**的。PPPoE会话的SESSION-ID一定不能改变，并且必须是发现阶段分配的值。
>
> **2.1 LCP协商阶段**（**LCP：Link Control Protocol**）
>
> LCP的Request主机和AC都要给对方发送，LCP协商阶段完成最大传输单元（MTU），是否进行认证和采用何种认证方式（Authentication Type）的协商。
>
> （1）LCP协议数据报文分类
>
> **链路配置报文**：用来建立和配置一条链路，主要包括Configure-Request、Configure-Ack、Configure-Nak和Configure-Reject报文
>
> **链路维护报文**：用来管理和调试链路，主要包括Code-Reject、Protocol-Reject、Echo-Request、Echo-Reply和Discard-Request报文
>
> **链路终止报文**：用来终止一条链路，主要包括Terminate-Request和Terminate-Reply报文
>
> （2）LCP协商过程
>
> LCP协商的过程如下：协商双方互相发送一个LCP Config-Request报文，确认收到的Config-Request报文中的协商选项，根据这些选项的支持与接受情况，做出适当的回应。若两端都回应了Config-ACK，则标志LCP链路建立成功，否则会继续发送Request报文，直到对端回应了ACK报文为止。
>
> ![img](https://img-blog.csdn.net/20130719173848562?watermark/2/text/aHR0cDovL2Jsb2cuY3Nkbi5uZXQvcGh1bnht/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70/gravity/SouthEast)
>
> 图2 LCP协商的基本过程
>
> **说明：**
>
> （1）Config-ACK：若完全支持对端的LCP选项，则回应Config-ACK报文，报文中必须完全协带对端Request报文中的选项。
>
> （2）Config-NAK：若支持对端的协商选项，但不认可该项协商的内容，则回应Config-NAK报文，在Config-NAK的选项中填上自己期望的内容，如:对端MRU值为1500，而自己期望MRU值为1492，则在Config-NAK报文中埴上自己的期望值1492。
>
> （3）Config-Reject：若不能支持对端的协商选项，则回应Config-Reject报文，报文中带上不能支持的选项，如Windows拨号器会协商CBCP（被叫回呼），而ME60不支持CBCP功能，则回将此选项拒绝掉。
>
> **2.2 认证阶段**（PPP Authentication：PAP/CHAP）
>
> 会话双方通过LCP协商好的认证方法进行认证，如果认证通过了，才可以进行下面的网络层的协商。认证过程在链路协商结束后就进行。
>
> Ⅰ **PAP**（Password Authentication Protocol，口令认证协议）认证
>
> PAP为**两次**握手协议，它通过用户名及口令来对用户进行验证。PAP验证过程如下：
>
> 当两端链路可相互传输数据时，被验证方发送本端的**用户名及口令**到验证方，验证方根据本端的用户表（或Radius服务器）查看是否有此用户，口令是否正确。如**正确**则会给对端发送Authenticate-ACK报文，通告对端已被允许进入下一阶段协商；**否则**发送NAK报文，通告对端验证失败。此时，并不会直接将链路关闭。只有当验证不过次数达到一定值（缺省为10）时，才会关闭链路。
>
> PAP的特点是在网络上以**明文**的方式传递用户名及口令，如在传输过程中被截获，便有可能对网络安全造成极大的威胁。因此，它适用于对网络安全要求相对较低的环境。
>
> ![img](https://img-blog.csdn.net/20130719174004812?watermark/2/text/aHR0cDovL2Jsb2cuY3Nkbi5uZXQvcGh1bnht/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70/gravity/SouthEast)
>
> 图3 PAP认证流程
>
> Ⅱ **CHAP**（Challenge Handshake Authentication Protocol，质询握手认证协议）认证
>
> CHAP为**三次**握手协议。只在网络上传输用户名，并不传输用户口令，因此它的安全性要比PAP高。CHAP的验证过程为：
>
> 首先由**验证方**（Server）向被验证方（Client）发送一些随机产生的报文，并同时将本端的**主机名**附带上一起发送给被验证方。**被验证方**接到对端对本端的验证请求（Challenge）时，便根据此报文中验证方的主机名和本端的用户表查找用户口令字，如找到用户表中与验证方主机名相同的用户，便利用报文ID、此用户的密钥用Md5算法生成应答（Response），随后将应答和自己的**主机名**送回。**验证方**接到此应答后，用报文ID、本方保留的口令字（密钥）和随机报文用Md5算法得出结果，与被验证方应答比较，根据比较结果返回相应的结果（ACK or NAK）
>
> （1）接受认证端发送Challenge
>
> （2）申请认证端发验证请求报文
>
> （3）接受认证端回应认证接受报文
>
> 经过以上三次报文交互后，CHAP认证完成。
>
> ![img](https://img-blog.csdn.net/20130719174031078?watermark/2/text/aHR0cDovL2Jsb2cuY3Nkbi5uZXQvcGh1bnht/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70/gravity/SouthEast)
>
> 图4 CHAP认证流程
>
> **2.3 NCP协商阶段**（**NCP**：Network Control Protocol）
>
> NCP有很多种，如IPCP、BCP、IPv6CP，最为常用的是**IPCP**（Internet Protocol Control Protocol）协议。NCP的主要功能是协商PPP报文的网络层参数，如IP地址，DNS Server IP地址，WINS Server IP地址等。PPPoE用户主要通过IPCP来获取访问网络的IP地址或IP地址段。
>
> NCP流程与LCP流程类似，用户与ME设备之间互相发送NCP Config-Request报文并且互相回应NCP Config-Ack报文后，标志NCP己协商完，用户上线成功，可以正常访问网络了。
>
> IPCP的协商过程是基于PPP状态机进行协商的。经过双方协商，通过配置请求、配置确认、配置否认等包文交换配置信息，最终由initial (或closed)状态变为Opened状态。IPCP状态变为Opened的条件必须是发送方和接收方都发送和接收过确认包文。
>
> IPCP协商过程中，协商包文可包含多个选项，即参数。各个选项的拒绝或否认都不能影响IPCP的UP，IPCP可以无选项协商，无选项协商也同样能够UP。选项有IP Address、网关、掩码等，其中IP Address是最重要的一个选项，有些厂家的实现必须这个选项得到确认，大多数厂家的实现允许这个选项为空。
>
> NCP的基本协商流程见下图：
>
> ![img](https://img-blog.csdn.net/20130719174053765?watermark/2/text/aHR0cDovL2Jsb2cuY3Nkbi5uZXQvcGh1bnht/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70/gravity/SouthEast)
>
> 图5 NCP的基本协商流程
>
> 用户和接入设备对IP服务阶段的一些要求进行多次协商，以决定双方都能够接收的约定。
>
> 如：IP业务阶段使用的IP压缩协议等。双方的协议是通过报文中包含的Option项进行协商的，每一个Option都是一个需要协商的问题。
>
> 最后双方都需要对方答复Configure_Ack的同意报文。
>
> **2.4 会话维持（Session Keep-alive）**
>
> 设备主动发送**Echo** Request进行PPPoE心跳保活，若3次未得到服务器的响应，则设备主动释放地址。发LCP Echo Request 的时候，魔术字字段要和之前通信的Configure_Request使用的魔术字字段保持一致。
>
> 有些设备或终端不支持主动发送 Echo-Request 报文, 只能支持回应Echo-Reply报文。
>
> **2.5 会话结束（Session Termination）**
>
> PPPoE 还有一个**PADT**（PPPOE Active Discovery Terminate）分组，它可以在会话建立后的任何时候发送，来终止PPPoE会话，也就是会话释放。它可以由主机或者接入集中器发送，目的地址填充为对端的以太网的MAC地址。
>
> 当对方接收到一个 PADT（PPPOE Active Discovery Terminate）分组，就不再允许使用这个会话来发送PPP业务。PADT分组不需要任何标签，其CODE字段值为0xa7（PADT Code），SESSION-ID字段值为需要终止的PPP会话的会话标识号码。在发送或接收PADT后，即使正常的PPP终止分组也不必发送。PPP对端应该使用PPP协议自身来终止PPPoE会话，但是当PPP不能使用时，可以使用PADT。

**3.PPPoE接入流程示例**

> PPP状态变迁如图6所示：
>
> ![img](https://img-blog.csdn.net/20130719174124437?watermark/2/text/aHR0cDovL2Jsb2cuY3Nkbi5uZXQvcGh1bnht/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70/gravity/SouthEast)
>
> 图6 PPP状态变迁图
>
> 以PPPoE-CHAP为例，PPP用户接入流程如图7所示：
>
> ![img](https://img-blog.csdn.net/20130719174143921?watermark/2/text/aHR0cDovL2Jsb2cuY3Nkbi5uZXQvcGh1bnht/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70/gravity/SouthEast)
>
> 图7 PPPoE/CHAP接入认证流程

**4.Linux中的PPPoE拨号守护进程**（pppd：Point-to-Point Protocol Daemon）

> pppd是一个后台服务进程(daemon)，是一个用户空间的进程，所以把策略性的内容从内核的PPP协议处理模块移到pppd中是很自然的事了。pppd实现了所有鉴权、压缩/解压和加密/解密等扩展功能的控制协议。
>
> pppd只是一个普通的用户进程，它如何扩展PPP协议呢？这就是pppd与内核中的PPP协议处理模块之间约定了，它们之间采用了最传统的内核空间与用户空间之间通信方式：设备文件。
>
> 设备文件名是/dev/ppp。通过**read**系统调用，pppd可以读取PPP协议处理模块的数据包，当然，PPP协议处理模块只会把应该由pppd处理的数据包发给pppd。通过**write**系统调用，pppd可以把要发送的数据包传递给PPP协议处理模块。通过**ioctrl**系统调用，pppd可以设置PPP协议的参数，可以建立/关闭连接。





# PPPoE帐号密码获取

学校的校园网通过拨号方式来实现计费。通过对TCP\IP的学习，知道是利用PPPOE进行连接，密码验证是使用的PAP密码验证。

## 协议实现

PPPOE连接分为发现阶段（Discovery stage）及会话阶段（PPP Session stage）。发现阶段实现客户端与服务器的互相确认，会话阶段则实现数据通信。完成发现阶段后，会进行LCP协议协商，紧接着便会进行密码确认。

发现阶段的PPPOE的code标志代码为0x6388,其过程主要分为以下几个步骤：

## PPPoE活动发现初始(PADI) 包

主机发送PADI（PPPoE Active Discovery Initiation）包，此时目标地址被设置为广播地址。CODE域设置为0x09，同时，SESSION_ID**必须**被设置为0x0000。

 

PADI包必须包含正确的、类型为服务名称（Service- Name）的标签，用于指出主机正在请求的服务。也可以包含任意数量的其他标签类型。整个PADI包（包括PPPoE包头），**必须不**超过1484字节（8位），以便有足够的空间用于中继代理增加中继会话ID（Relay-Session-Id）标签。

 

## PPPoE活动发现提议(PADO) 包

当访问集中器接收到它可以提供服务的PADI包，它通过发送一个PADO（PPPoE Active Discovery Offer）包来响应。目标地址是发送PADI的主机的单播地址。CODE域被设置为0x07，同时，SESSION_ID**必须**被设置为0x0000。

 

PADO包**必须**包含一个AC名称（AC-Name）标签，其中有访问集中器的名称；同时，**必须**包含一个服务名称（Service-Name）标签来标识PADI中的服务名称，同时可以包含任意数量的其他服务名称（Service-Name）标签来指出该访问集中器提供的其他服务。如果该访问集中器不能为这个PADI包提供服务，则它**必须不**能用PADO做出应答。

 

## PPPoE活动发现请求(PADR) 包

因为PADI是广播包，所以主机可能接收到多个PADO。主机需要审核这些PADO包，并且从中选择一个。这个选择可以基于所提供的AC名称（AC-Name）或者服务。然后，主机发送PADR（PPPoE Active Discovery Request）包给被选中的访问集中器。目标地址被设置为这个发送PADO的访问集中器的单播以太网地址。CODE域被设置为0x19，同时，SESSION_ID**必须**被设置为0x0000。

 

PADR包必须包含一个正确的服务名称（Service-Name）标签，该标签指出主机所请求的服务。同时可以包含任意数量的其他标签。

 

## PPPoE活动发现会话确认(PADS) 包

当访问集中器接收到PADR包时，它开始准备开始一个PPP会话。它为PPPoE会话创建一个唯一的会话ID（SESSION_ID），并用PADS（PPPoE Active Discovery Session-confirmation）包回复给主机。目标地址域设置为发送PADR的主机的单播以太网地址。CODE域设置为0x65，同时，SESSION_ID**必须**设置为刚为本次PPPoE会话创建的唯一值。

PADS包包含一个正确的服务名称（Service-Name）标签，该标签指出这个接收了PPPoE会话的访问集中器的服务。同时可以包含任意数量的其他标签。

如果访问集中器不喜欢PADR中的服务名称，则它必须在回复的PADS中包含服务名称错误（Service-Name-Error）标签（以及任意数量的其他标签）。这时，SESSION_ID**必须**被设置为0x0000。

 

## PPPoE活动发现终止(PADT) 包

这个包可以在会话建立之后的任意时刻发送，用于指出这个PPPoE会话已经被终止。主机或者访问集中器都可以发送这个包。目标地址被设置为单播以太网地址，CODE域被设置为0xa7，SESSION_ID MUST**必须**设置为将被终止的会话的ID。这个包不需要任何标签。

当接收到一个PADT（PPPoE Active Discovery Terminate）时，任何使用该会话的PPP通信都是不允许的。在发送或者接收到一个PADT后，即使正常的PPP终止包也**必须不**再被发送。PPP端**应该**使用PPP协议本身来关闭一个PPPoE会话，但PADT**可以**用于PPP不能使用的情况。

 

LCP发现阶主机相互确认了身份，然后进入会话阶段，进行协议协商阶段(LCP)。大致过程是发送请求包，发送确认包。然后进行密码验证，此过程中帐号密码是明文保存的。

## 协议漏洞

要想进行PPPOE连接，客户机首先会发出一个目标MAC地址为FF:FF:FF:FF:FF:FF的广播数据包。PPPOE服务器接收到此包，会发送一个含有自己MAC地址的数据包给客户机告诉其自己的MAC地址。然后两台计算机进行互相通信，发现阶段过后客户机就会提交帐号密码。

由于客户机最初发出的是广播包，局域网内任何一台电脑都可以接收到。当接收到一个PPOE发现数据包，我们如果立即发送一个应答包来假冒PPPOE服务器。若此欺骗包先于真正的应答包被客户机接收，那么客户机就会认为我们的计算机就是PPPOOE服务器，此后的通讯包就会发送到我们的计算机MAC地址上。而由于PAP密码认证是用明文来传输帐号密码，所以我们就可以轻易通过欺骗客户机来截取其上网密码。