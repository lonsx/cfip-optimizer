<div align="center">

<img src="docs/images/logo.png" alt="cfip-opt logo" width="128" height="128" />

# Cloudflare IP 优选与 DNS 自动同步工具 (`cfip-opt`)

高性能、轻量级 Cloudflare 边缘优选 IP 测速引擎与 AdGuard Home DNS 自动化管理系统。  
支持 **Docker 容器**、**Docker Compose 编排** 与 **飞牛私有云 (fnOS) 官方原生应用** 跨系统全平台多架构部署。

[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Docker%20%7C%20fnOS-blue?style=flat-square)](https://github.com)
[![Architecture](https://img.shields.io/badge/Arch-linux%2Famd64%20%7C%20linux%2Farm64-brightgreen?style=flat-square)](https://github.com)
[![Docker Image Size](https://img.shields.io/badge/Docker%20Size-14.6MB-blueviolet?style=flat-square)](https://github.com)
[![License](https://img.shields.io/badge/License-MIT-orange?style=flat-square)](LICENSE)

</div>

---

## 🌟 核心特性

- ⚡ **五阶段高精度测速流水线**：
  1. **前置地区过滤**：内置节点地区识别与历史库比对，快速剔除非目标区域；
  2. **多轮延迟与抖动判定**：支持 TCP 连接 (`ping`)、TLS 握手 (`tls` 抗透明代理劫持) 与 `httping` 多轮测试，精准计算均值与标准差 $\sigma$；
  3. **双地址族名额对半**：IPv4 / IPv6 自动对半分成候选池，单族不足时弹性让渡；
  4. **真实下载带宽压测**：对前 $N$ 名优选 IP 发起真实大文件测速，输出峰值与均值速率；
  5. **DNS 自动接管与差异对账**：将最优 IP 一键写入局域网 AdGuard Home 实例重写表，自动清理历史失效记录。
- 🛡️ **可达性守护与故障秒级轮换**：后台常驻毫秒级可达性探测，主选节点中断时秒级切换至备选 IP，遇大面积阻断自动触发重新测速。
- 🚀 **极小资源占用 & 多架构原生支持**：纯 Go 语言开发，零外部运行时依赖，Docker 镜像仅 **14.6 MB**；支持 `linux/amd64` 与 `linux/arm64` 多架构；提供专为飞牛 fnOS 打造的统一网关原生应用，零独立端口占用。

---

## 🚀 三种部署方法

本项目全面支持主流 Linux 服务器、群晖/威联通/极空间等通用 NAS（Docker 方式），以及飞牛私有云 fnOS（FPK 原生应用）。请按需选择最适合的部署方式：

### 方法一：Docker 命令运行

适合任意已安装 Docker 的 Linux 主机、软路由或 NAS 环境，一条命令即可极速拉起。

#### 1. 使用预构建线上公共镜像（推荐开箱即用）
当项目推送到 GitHub 后，GitHub Actions 会自动编译多架构镜像（`linux/amd64` 与 `linux/arm64`）并发布至 GitHub Packages (`ghcr.io`)：

```bash
# 推荐使用 host 网络模式（避开 Docker 内部 NAT 损耗，获得宿主机毫秒级真实延迟精度）
docker run -d \
  --name cfip-opt \
  --restart unless-stopped \
  --net=host \
  -v $(pwd)/data:/data \
  -e TZ=Asia/Shanghai \
  -e CFIP_LISTEN=0.0.0.0:8787 \
  -e CFIP_ALLOWED_CIDRS=0.0.0.0/0,::/0 \
  ghcr.io/<你的GitHub用户名>/cfip-optimizer:latest
```

> **说明**：也可以使用桥接网络映射端口（`-p 8787:8787`）。

#### 2. 本地源码即时构建运行（无线上镜像时的免配置方案）
若您已拉取本项目源码，只需在仓库根目录下执行构建并启动：

```bash
# 本地构建（自动适配当前机器的 CPU 架构）
docker build -t cfip-opt:latest .

# 启动容器
docker run -d \
  --name cfip-opt \
  --restart unless-stopped \
  -p 8787:8787 \
  -v $(pwd)/data:/data \
  -e TZ=Asia/Shanghai \
  -e CFIP_LISTEN=0.0.0.0:8787 \
  -e CFIP_ALLOWED_CIDRS=0.0.0.0/0,::/0 \
  cfip-opt:latest
```

访问地址：浏览器打开 `http://<服务器IP>:8787` 即可进入 Web 管理面板。

---

### 方法二：Docker Compose 编排部署（推荐方案）

适合日常运维与容器微服务编排。项目根目录下已预置开箱即用的 `docker-compose.yml`，**支持本地自动构建与线上镜像直接拉取**。

#### 1. 配置文件结构 (`docker-compose.yml`)

```yaml
services:
  cfip-opt:
    image: cfip-opt:latest
    # 若本地有源码，Compose 会直接本地极速构建；若仅有 Compose 文件，可指定线上镜像 ghcr.io/<用户名>/cfip-optimizer:latest
    build:
      context: .
      dockerfile: Dockerfile
    container_name: cfip-opt
    restart: unless-stopped
    ports:
      - "8787:8787"
    environment:
      - TZ=Asia/Shanghai
      - CFIP_LISTEN=0.0.0.0:8787
      - CFIP_DATA=/data
      # 允许访问控制台的网段，默认放行全部；可指定内网段如 192.168.0.0/16,10.0.0.0/8
      - CFIP_ALLOWED_CIDRS=0.0.0.0/0,::/0
    volumes:
      - ./data:/data
    # 可选：取消下方注释使用 host 网络获得原生延迟测速精度
    # network_mode: host
```

#### 2. 一键启动与管理

```bash
# 后台构建并启动
docker compose up -d

# 查看运行日志
docker compose logs -f

# 停止服务
docker compose down
```

启动后，系统会自动在挂载的 `./data` 目录下初始化默认配置 `config.json` 与官方 IPv4/IPv6 IP 段待测库。

---

### 方法三：飞牛私有云 (fnOS) 原生应用（FPK 安装）

针对飞牛私有云（fnOS）统一网关（Unified Gateway）深度研发，**也是本项目正式官方支持的平台**。

#### 优势亮点
- **零 Docker 容器开销**：单静态 Go 原生进程，内存消耗低至约 10MB；
- **零端口冲突**：直连 fnOS 统一网关 `/app/cfip-opt/`，无需暴露任何外部 TCP 端口；
- **全平台支持（`platform = all`）**：安装包内同时内置 `x86_64` 与 `aarch64` 纯静态二进制，安装时根据 CPU 架构自动完成链接；
- **原生系统体验**：安装后自动集成至飞牛桌面与应用中心，支持官方向导配置与图标唤起。

#### 安装步骤

项目内置打包好的官方标准安装包，位于仓库的 `fpk/` 目录下：
👉 **`fpk/cfip-opt_1.1.2_all.fpk`**

##### 途径 A：飞牛桌面 Web 界面安装（推荐）
1. 登录飞牛 fnOS 桌面，打开 **应用中心**；
2. 点击右上角 **手动安装**；
3. 选择并上传项目中的 `fpk/cfip-opt_1.1.2_all.fpk` 安装包；
4. 按向导确认安装，完成后在飞牛桌面即可看到专属活力橙图标，点击即可直连控制台。

##### 途径 B：飞牛 NAS SSH 终端命令行安装
在飞牛 NAS 终端执行如下命令即可一键安装升级：
```bash
sudo appcenter-cli install-fpk fpk/cfip-opt_1.1.2_all.fpk -v 4
```

---

## ⚙️ 环境变量与参数配置

通过 Docker 环境变量或配置文件进行灵活调整：

| 环境变量 | 默认值 | 说明 |
| :--- | :--- | :--- |
| `CFIP_LISTEN` | `0.0.0.0:8787` | TCP 监听地址与端口（仅在非 Socket 模式下生效） |
| `CFIP_DATA` | `/data` (Docker) | 配置文件、官方 IP 段与测速结果的持久化存放目录 |
| `CFIP_ALLOWED_CIDRS` | `0.0.0.0/0,::/0` | Dashboard 安全门禁网段（支持逗号分隔，如 `192.168.0.0/16,10.0.0.0/8` 或 `*` 放行） |
| `CFIP_SOCK` | `空` | Unix Domain Socket 路径（飞牛网关专用，设置时优先于 TCP 监听） |
| `TZ` | `Asia/Shanghai` | 容器时区设置 |

---

## 📖 Web 控制台功能指南

部署成功后，在 Web 界面即可享受专业可视化 IP 优选体验：

1. **🌐 地区与源**：按机场代码筛选偏好地区（如 HKG 香港、TPE 台湾、NRT 东京、SJC 圣何塞等），自定义待测 IP 段。
2. **⏱ 延迟设置**：配置多轮探测次数、网络探测模式（`ping`、抗劫持 `tls`、`httping`）、单次超时时间与标准差阈值。
3. **🚀 测速设置**：设置下载压测并发数、候选节点名额上限、真实测试文件地址（支持自定义大文件）。
4. **🔄 AdGuard 同步**：填写 AdGuard Home 的内网 URL（如 `http://192.168.1.2:3000`）与管理员账号口令，测速完成后自动同步最优 IP 到指定的重写域名，并支持实时查看当前实例的重写映射表。
5. **🛡 可达性守护**：设置健康检测间隔（15秒 ~ 3600秒自由可调），节点中断时自动从上一轮优选备选池中实现无感无缝切换。

---

## 🛠️ 项目结构与本地二次开发

```text
cfip-opt-github/
├── .github/
│   └── workflows/
│       └── docker-publish.yml # GitHub Actions: 自动构建 linux/amd64 + linux/arm64 多架构并推送到 ghcr.io
│
├── fpk/                       # [飞牛平台] 官方标准全平台飞牛应用安装包 (5.2 MB)
│   ├── cfip-opt_1.1.2_all.fpk # 内置 x86_64 与 aarch64 双架构自适应
│   └── README.md              # 飞牛安装指南
│
├── go-web/                    # [Docker 源码] Go 核心测速引擎与内嵌 Web 控制台
│   ├── cmd/cfip-opt/          # 主程序入口 (守护、控制台生命周期)
│   ├── internal/              # 核心模块 (adguard客户端、测速引擎、调度器、HTTP服务)
│   └── internal/server/assets # 前端页面 (轻量响应式 SPA 控制台)
│
├── pkg/                       # [飞牛蓝图] 飞牛 fnpack 规范应用定义 (飞牛应用源码)
│   ├── manifest               # 官方应用元数据 (platform = all)
│   ├── cmd/                   # 9 大标准生命周期控制脚本 (含多架构自动分发)
│   └── app/                   # 内置应用实体与统一网关入口声明
│
├── scripts/                   # [工具链] 飞牛全平台打包脚本
│   └── build_fpk.py           # 官方交叉编译与 fnpack FPK 全平台打包脚本
│
├── Dockerfile                 # 多架构生产级 Docker 构建蓝图 (amd64 / arm64)
├── docker-compose.yml         # 开箱即用 Docker Compose 编排文件
└── README.md                  # 项目使用与部署说明文档
```

### 1. 本地多架构 Docker 镜像构建与推送
使用 Docker Buildx 可一条命令完成多架构编译并推送至您自己的镜像仓库：
```bash
# 启用 Buildx 多架构构建器
docker buildx create --use --name multi-builder

# 同时编译 amd64 与 arm64 架构并推送至线上仓库
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t <your-registry>/cfip-opt:latest \
  --push .
```

### 2. 构建全平台飞牛 FPK 安装包
```bash
python scripts/build_fpk.py
```

---

## 📄 开源许可证

本项目基于 [MIT License](LICENSE) 协议开源。
