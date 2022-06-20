Step1：在生成的syscall.h文件中，删除所有的变量定义。
Step2：在生成的Syscall.h文件中，导入prototypes.h头文件。
Step3：在SysWhisoer2Demo库文件SysWhioers2Demo.c文件中，导入syscall.h头文件，目的是修改链接的Nt函数。
Step4：注释SysWhisoer2Demo库文件SysWhioers2Demo.c文件中，指定函数的动态获取函数地址的语句。