# 飞牛私有云 (fnOS) 官方原生应用安装包

本目录包含适用于飞牛私有云操作系统的全平台标准应用安装包：

- **文件**：`cfip-opt_1.1.2_all.fpk`
- **支持架构**：全平台（`platform = all`，内置 `x86_64` 与 `aarch64` 纯静态二进制，安装时根据 CPU 架构自动链接）
- **核心特性**：直连 fnOS 统一网关（Unified Gateway，路径 `/app/cfip-opt/`），无独立端口占用、无 Docker 额外资源开销。

### 安装方法

1. **飞牛桌面 Web 安装**：打开「应用中心」->「手动安装」-> 选择上传本安装包即可。
2. **NAS 命令行安装**：
   ```bash
   sudo appcenter-cli install-fpk cfip-opt_1.1.2_all.fpk -v 4
   ```
