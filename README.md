# x64dbgpatchexporter
Patch exporter for [x64dbg](https://github.com/x64dbg/x64dbg) : export patches with a template.

# Feature
Export the patches as C program source, and you can compile it with your favourite compiler. The program will automatically apply the patches you made as you double-click on it.

将补丁导出为C语言源程序，您之后就能编译它。导出的程序可以将您的补丁自动应用到当前运行的程序。

You can also make your own template to support a programming language other than C.

您也可以仿照C.txt的格式自行制作一个模板以支持别的编程语言。

All the files exported are saved in UTF-16 encoding with BOM.

导出的文件都是采用带有文件头的UTF-16编码的。

# Usage
Click on "Export", then select the template(such as the "C.txt" released), then export the patch to a file.

用法：点击插件菜单里的导出补丁，然后选择一个模板(比如随插件一起发布的C.txt)，再选择保存到的文件。

After you exported one file, the last template is remembered and you can use it in subsequent exports.

导出一次补丁后，上次使用的模板就会记忆下来，下次导出可以用"以上次使用的模板导出补丁"快速导出。
