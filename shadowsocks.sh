#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
#
# Thanks to: Teddysun, M3chD09
# Distributed under the GPLv3 software license, see the accompanying
# file COPYING or https://opensource.org/licenses/GPL-3.0.
#
# Auto install Shadowsocks Server
# System Required:  CentOS 6+, Debian7+, Ubuntu12+
#
# Reference URL:
# https://github.com/shadowsocks
# https://github.com/shadowsocks/shadowsocks-libev
# https://github.com/shadowsocksrr/shadowsocksr
#

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

[[ $EUID -ne 0 ]] && echo -e "[${red}Error${plain}] This script must be run as root!" && exit 1

cur_dir=$(pwd)
software=(Shadowsocks-libev ShadowsocksR Shadowsocks-Rust)

gh_dl_url='https://raw.githubusercontent.com/RedTeaDev/ss-install/master/'
script_folder='scripts'

libsodium_file='libsodium-1.0.20'
libsodium_url='https://github.com/jedisct1/libsodium/releases/download/1.0.20-RELEASE/'"$libsodium_file"'.tar.gz'

mbedtls_file='mbedtls-2.16.11'
mbedtls_url='https://github.com/ARMmbed/mbedtls/archive/'"$mbedtls_file"'.tar.gz'

shadowsocks_libev_init="/etc/init.d/shadowsocks-libev"
shadowsocks_libev_config="/etc/shadowsocks-libev/config.json"
shadowsocks_libev_centos="$gh_dl_url/$script_folder/shadowsocks-libev-centos"
shadowsocks_libev_debian="$gh_dl_url/$script_folder/shadowsocks-libev-debian"

shadowsocks_r_file="shadowsocksr-3.2.2"
shadowsocks_r_url="https://github.com/shadowsocksrr/shadowsocksr/archive/3.2.2.tar.gz"
shadowsocks_r_init="/etc/init.d/shadowsocks-r"
shadowsocks_r_config="/etc/shadowsocks-r/config.json"
shadowsocks_r_centos="$gh_dl_url/$script_folder/shadowsocksR-centos"
shadowsocks_r_debian="$gh_dl_url/$script_folder/shadowsocksR-debian"

# shadowsocks-rust (ssserver)
shadowsocks_rust_config="/etc/shadowsocks-rust/config.json"
shadowsocks_rust_dir="/etc/shadowsocks-rust"
shadowsocks_rust_systemd="/etc/systemd/system/ssserver.service"
shadowsocks_rust_init="/etc/init.d/shadowsocks-rust"
ssrust_latest_api="https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases/latest"

common_ciphers=(
    aes-256-gcm
    aes-192-gcm
    aes-128-gcm
    aes-256-cfb
    aes-192-cfb
    aes-128-cfb
    aes-256-ctr
    aes-192-ctr
    aes-128-ctr
    camellia-256-cfb
    camellia-192-cfb
    camellia-128-cfb
    xchacha20-ietf-poly1305
    chacha20-ietf-poly1305
    chacha20-ietf
    chacha20
    salsa20
    bf-cfb
    rc4-md5
)
r_ciphers=(
    none
    aes-256-cfb
    aes-192-cfb
    aes-128-cfb
    aes-256-cfb8
    aes-192-cfb8
    aes-128-cfb8
    aes-256-ctr
    aes-192-ctr
    aes-128-ctr
    chacha20-ietf
    xchacha20
    xsalsa20
    chacha20
    salsa20
    rc4-md5
)

# Reference URL:
# https://github.com/shadowsocksrr/shadowsocks-rss/blob/master/ssr.md
# https://github.com/shadowsocksrr/shadowsocksr/commit/a3cf0254508992b7126ab1151df0c2f10bf82680
protocols=(
    origin
    verify_deflate
    auth_sha1_v4
    auth_sha1_v4_compatible
    auth_aes128_md5
    auth_aes128_sha1
    auth_chain_a
    auth_chain_b
    auth_chain_c
    auth_chain_d
    auth_chain_e
    auth_chain_f
)

obfs=(
    plain
    http_simple
    http_simple_compatible
    http_post
    http_post_compatible
    random_head
    random_head_compatible
    tls1.2_ticket_auth
    tls1.2_ticket_auth_compatible
    tls1.2_ticket_fastauth
    tls1.2_ticket_fastauth_compatible
)

disable_selinux() {
    if [ -s /etc/selinux/config ] && grep 'SELINUX=enforcing' /etc/selinux/config; then
        sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
        setenforce 0
    fi
}

check_sys() {
    local checkType=$1
    local value=$2

    local release=''
    local systemPackage=''

    if [[ -f /etc/redhat-release ]]; then
        release="centos"
        systemPackage="yum"
    elif grep -Eqi "centos|red hat|redhat" /etc/issue; then
        release="centos"
        systemPackage="yum"
    elif grep -Eqi "centos|red hat|redhat" /proc/version; then
        release="centos"
        systemPackage="yum"
    elif grep -Eqi "debian|raspbian" /etc/issue; then
        release="debian"
        systemPackage="apt"
    elif grep -Eqi "debian|raspbian" /proc/version; then
        release="debian"
        systemPackage="apt"
    elif grep -Eqi "ubuntu" /etc/issue; then
        release="ubuntu"
        systemPackage="apt"
    elif grep -Eqi "ubuntu" /proc/version; then
        release="ubuntu"
        systemPackage="apt"
    fi

    if [[ "${checkType}" == "sysRelease" ]]; then
        if [ "${value}" == "${release}" ]; then
            return 0
        else
            return 1
        fi
    elif [[ "${checkType}" == "packageManager" ]]; then
        if [ "${value}" == "${systemPackage}" ]; then
            return 0
        else
            return 1
        fi
    fi
}

# centosversion
getversion() {
    if [[ -s /etc/redhat-release ]]; then
        grep -oE "[0-9.]+" /etc/redhat-release
    else
        grep -oE "[0-9.]+" /etc/issue
    fi
}

centosversion() {
    if check_sys sysRelease centos; then
        local code=$1
        local version="$(getversion)"
        local main_ver=${version%%.*}
        if [ "$main_ver" == "$code" ]; then
            return 0
        else
            return 1
        fi
    else
        return 1
    fi
}

# debianversion
get_opsy() {
    [ -f /etc/redhat-release ] && awk '{print ($1,$3~/^[0-9]/?$3:$4)}' /etc/redhat-release && return
    [ -f /etc/os-release ] && awk -F'[= "]' '/PRETTY_NAME/{print $3,$4,$5}' /etc/os-release && return
    [ -f /etc/lsb-release ] && awk -F'[="]+' '/DESCRIPTION/{print $2}' /etc/lsb-release && return
}

debianversion() {
    if check_sys sysRelease debian; then
        local version=$(get_opsy)
        local code=${1}
        local main_ver=$(echo ${version} | sed 's/[^0-9]//g')
        if [ "${main_ver}" == "${code}" ]; then
            return 0
        else
            return 1
        fi
    else
        return 1
    fi
}

get_ip() {
    local IP=$(ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1)
    [ -z ${IP} ] && IP=$(wget -qO- -t1 -T2 ipv4.icanhazip.com)
    [ -z ${IP} ] && IP=$(wget -qO- -t1 -T2 ipinfo.io/ip)
    echo ${IP}
}

get_ipv6() {
    local ipv6=$(wget -qO- -t1 -T2 ipv6.icanhazip.com)
    [ -z ${ipv6} ] && return 1 || return 0
}

get_libev_ver() {
    libev_ver=$(wget --no-check-certificate -qO- https://api.github.com/repos/shadowsocks/shadowsocks-libev/releases/latest | grep 'tag_name' | cut -d\" -f4)
    [ -z ${libev_ver} ] && echo -e "[${red}Error${plain}] Get shadowsocks-libev latest version failed" && exit 1
}

install_check() {
    if check_sys packageManager yum || check_sys packageManager apt; then
        if centosversion 5; then
            return 1
        fi
        return 0
    else
        return 1
    fi
}

install_select() {
    if ! install_check; then
        echo -e "[${red}Error${plain}] Your OS is not supported to run it!"
        echo "Please change to CentOS 6+/Debian 7+/Ubuntu 12+ and try again."
        exit 1
    fi

    clear
    get_libev_ver
    while true; do
        echo "Which Shadowsocks server you'd select:"
        for ((i = 1; i <= ${#software[@]}; i++)); do
            hint="${software[$i - 1]}"
            echo -e "${green}${i}${plain}) ${hint}"
        done
        read -p "Please enter a number (Default ${software[0]}):" selected
        [ -z "${selected}" ] && selected="1"
        case "${selected}" in
        1 | 2 | 3)
            echo
            echo "You choose = ${software[${selected} - 1]}"
            if [ "${selected}" == "1" ]; then
                echo -e "[${green}Info${plain}] Shadowsocks-libev Version: ${libev_ver}"
            fi
            echo
            break
            ;;
        *)
            echo -e "[${red}Error${plain}] Please only enter a number [1-3]"
            ;;
        esac
    done
}

error_detect_depends() {
    local command=$1
    local depend=$(echo "${command}" | awk '{print $4}')
    echo -e "[${green}Info${plain}] Starting to install package ${depend}"
    ${command} >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo -e "[${red}Error${plain}] Failed to install ${red}${depend}${plain}"
        exit 1
    fi
}

install_dependencies() {
    if check_sys packageManager yum; then
        echo -e "[${green}Info${plain}] Checking the EPEL repository..."
        if [ ! -f /etc/yum.repos.d/epel.repo ]; then
            yum install -y epel-release >/dev/null 2>&1
        fi
        [ ! -f /etc/yum.repos.d/epel.repo ] && echo -e "[${red}Error${plain}] Install EPEL repository failed, please check it." && exit 1
        [ ! "$(command -v yum-config-manager)" ] && yum install -y yum-utils >/dev/null 2>&1
        [ x"$(yum-config-manager epel | grep -w enabled | awk '{print $3}')" != x"True" ] && yum-config-manager --enable epel >/dev/null 2>&1
        echo -e "[${green}Info${plain}] Checking the EPEL repository complete..."

        yum_depends=(
            autoconf automake cpio curl curl-devel gcc git gzip libevent libev-devel libtool make openssl
            openssl-devel pcre pcre-devel perl perl-devel python python-devel python-setuptools
            qrencode unzip c-ares-devel expat-devel gettext-devel zlib-devel xz
        )
        for depend in ${yum_depends[@]}; do
            error_detect_depends "yum -y install ${depend}"
        done
    elif check_sys packageManager apt; then
        apt_depends=(
            autoconf automake build-essential cpio curl gcc gettext git gzip libpcre3 libpcre3-dev
            libtool make openssl perl python3 qrencode unzip xz-utils
            libc-ares-dev libev-dev libssl-dev zlib1g-dev
        )

        apt -y update >/dev/null 2>&1
        for depend in ${apt_depends[@]}; do
            error_detect_depends "apt -y install ${depend}"
        done
    fi
}

install_prepare_password() {
    echo "Please enter password for ${software[${selected} - 1]}"
    read -p "(Default password will be generated if left blank):" shadowsockspwd
    if [ -z "${shadowsockspwd}" ]; then
        if command -v openssl >/dev/null 2>&1; then
            shadowsockspwd=$(openssl rand -base64 16)
        else
            shadowsockspwd="shadowsocks"
            echo -e "[${yellow}Warning${plain}] Failed to generate a random password, set to default password: ${shadowsockspwd}"
        fi
    fi
    # Password strength check
    if [[ ${#shadowsockspwd} -lt 8 ]] || ! [[ "$shadowsockspwd" =~ [A-Z] ]] || ! [[ "$shadowsockspwd" =~ [a-z] ]] || ! [[ "$shadowsockspwd" =~ [0-9] ]] || ! [[ "$shadowsockspwd" =~ [^A-Za-z0-9] ]]; then
        echo -e "[${yellow}Warning${plain}] weak password detected! You may be vulnerable to Partitioning Oracle Attack!"
        echo -e "[${yellow}Warning${plain}] See: https://www.usenix.org/system/files/sec21summer_len.pdf"
    fi
    echo
    echo "password = ${shadowsockspwd}"
    echo
}

install_prepare_port() {
    while true; do
        dport=$(shuf -i 9000-19999 -n 1)
        echo -e "Please enter a port for ${software[${selected} - 1]} [1-65535]"
        read -p "(Default port: ${dport}):" shadowsocksport
        [ -z "${shadowsocksport}" ] && shadowsocksport=${dport}
        expr ${shadowsocksport} + 1 &>/dev/null
        if [ $? -eq 0 ]; then
            if [ ${shadowsocksport} -ge 1 ] && [ ${shadowsocksport} -le 65535 ] && [ ${shadowsocksport:0:1} != 0 ]; then
                echo
                echo "port = ${shadowsocksport}"
                echo
                break
            fi
        fi
        echo -e "[${red}Error${plain}] Please enter a correct number [1-65535]"
    done
}

install_prepare_cipher() {
    while true; do
        echo -e "Please select stream cipher for ${software[${selected} - 1]} (AEAD cipher is recommended):"

        if [ "${selected}" == "1" ]; then
            for ((i = 1; i <= ${#common_ciphers[@]}; i++)); do
                hint="${common_ciphers[$i - 1]}"
                echo -e "${green}${i}${plain}) ${hint}"
            done
            read -p "Which cipher you'd select(Default: ${common_ciphers[0]}):" pick
            [ -z "$pick" ] && pick=1
            expr ${pick} + 1 &>/dev/null
            if [ $? -ne 0 ]; then
                echo -e "[${red}Error${plain}] Please enter a number"
                continue
            fi
            if [[ "$pick" -lt 1 || "$pick" -gt ${#common_ciphers[@]} ]]; then
                echo -e "[${red}Error${plain}] Please enter a number between 1 and ${#common_ciphers[@]}"
                continue
            fi
            shadowsockscipher=${common_ciphers[$pick - 1]}
        elif [ "${selected}" == "2" ]; then
            for ((i = 1; i <= ${#r_ciphers[@]}; i++)); do
                hint="${r_ciphers[$i - 1]}"
                echo -e "${green}${i}${plain}) ${hint}"
            done
            read -p "Which cipher you'd select(Default: ${r_ciphers[1]}):" pick
            [ -z "$pick" ] && pick=2
            expr ${pick} + 1 &>/dev/null
            if [ $? -ne 0 ]; then
                echo -e "[${red}Error${plain}] Please enter a number"
                continue
            fi
            if [[ "$pick" -lt 1 || "$pick" -gt ${#r_ciphers[@]} ]]; then
                echo -e "[${red}Error${plain}] Please enter a number between 1 and ${#r_ciphers[@]}"
                continue
            fi
            shadowsockscipher=${r_ciphers[$pick - 1]}
        fi

        echo
        echo "cipher = ${shadowsockscipher}"
        # Cipher security check
        aead_ciphers=(aes-256-gcm aes-192-gcm aes-128-gcm chacha20-ietf-poly1305 xchacha20-ietf-poly1305)
        is_aead=false
        for ac in "${aead_ciphers[@]}"; do
            if [ "${shadowsockscipher}" == "$ac" ]; then
                is_aead=true
                break
            fi
        done
        if [ "$is_aead" == "false" ]; then
            echo -e "[${yellow}Warning${plain}] Chosen cipher is not AEAD cipher, you are vulnerable to GFW active probing!"
        fi
        echo
        break
    done
}

install_prepare_udp() {
    # Ask for UDP support on Shadowsocks-libev
    while true; do
        echo -e "Would you like to enable UDP support for ${software[${selected} - 1]}?"
        read -p "(y/n, Default: n):" yn
        [ -z "$yn" ] && yn="n"
        if [[ $yn == [Yy] ]]; then
            shadowsocksudp="tcp_and_udp"
            echo
            echo "UDP support = enabled"
            echo
            # Check password strength if UDP is enabled
            if [[ ${#shadowsockspwd} -lt 8 ]] || ! [[ "$shadowsockspwd" =~ [A-Z] ]] || ! [[ "$shadowsockspwd" =~ [a-z] ]] || ! [[ "$shadowsockspwd" =~ [0-9] ]] || ! [[ "$shadowsockspwd" =~ [^A-Za-z0-9] ]]; then
                echo -e "[${yellow}Warning${plain}] UDP with weak password will be vulnerable to Partitioning Oracle Attack, Either set a strong password or disable UDP support!"
            fi
            break
        elif [[ $yn == [Nn] ]]; then
            shadowsocksudp="tcp_only"
            echo
            echo "UDP support = disabled"
            echo
            break
        else
            echo -e "[${red}Error${plain}] Please only enter y (yes) or n (no)"
        fi
    done
}

install_prepare_protocol() {
    while true; do
        echo -e "Please select protocol for ${software[${selected} - 1]}:"
        for ((i = 1; i <= ${#protocols[@]}; i++)); do
            hint="${protocols[$i - 1]}"
            echo -e "${green}${i}${plain}) ${hint}"
        done
        read -p "Which protocol you'd select(Default: ${protocols[0]}):" protocol
        [ -z "$protocol" ] && protocol=1
        expr ${protocol} + 1 &>/dev/null
        if [ $? -ne 0 ]; then
            echo -e "[${red}Error${plain}] Please enter a number"
            continue
        fi
        if [[ "$protocol" -lt 1 || "$protocol" -gt ${#protocols[@]} ]]; then
            echo -e "[${red}Error${plain}] Please enter a number between 1 and ${#protocols[@]}"
            continue
        fi
        shadowsockprotocol=${protocols[$protocol - 1]}
        echo
        echo "protocol = ${shadowsockprotocol}"
        echo
        break
    done
}

install_prepare_obfs() {
    while true; do
        echo -e "Please select obfs for ${software[${selected} - 1]}:"
        for ((i = 1; i <= ${#obfs[@]}; i++)); do
            hint="${obfs[$i - 1]}"
            echo -e "${green}${i}${plain}) ${hint}"
        done
        read -p "Which obfs you'd select(Default: ${obfs[0]}):" r_obfs
        [ -z "$r_obfs" ] && r_obfs=1
        expr ${r_obfs} + 1 &>/dev/null
        if [ $? -ne 0 ]; then
            echo -e "[${red}Error${plain}] Please enter a number"
            continue
        fi
        if [[ "$r_obfs" -lt 1 || "$r_obfs" -gt ${#obfs[@]} ]]; then
            echo -e "[${red}Error${plain}] Please enter a number between 1 and ${#obfs[@]}"
            continue
        fi
        shadowsockobfs=${obfs[$r_obfs - 1]}
        echo
        echo "obfs = ${shadowsockobfs}"
        echo
        break
    done
}

get_char() {
    SAVEDSTTY=$(stty -g)
    stty -echo
    stty cbreak
    dd if=/dev/tty bs=1 count=1 2>/dev/null
    stty -raw
    stty echo
    stty $SAVEDSTTY
}

install_prepare() {
    if [ "${selected}" == "1" ]; then
        install_prepare_password
        install_prepare_port
        install_prepare_udp
        install_prepare_cipher
    elif [ "${selected}" == "2" ]; then
        install_prepare_password
        install_prepare_port
        install_prepare_cipher
        install_prepare_protocol
        install_prepare_obfs
    elif [ "${selected}" == "3" ]; then
        # rust server needs the same basic info as libev
        install_prepare_password
        install_prepare_port
        install_prepare_udp
        install_prepare_cipher
    fi
    echo "Press any key to start...or Press Ctrl+C to cancel"
    char=$(get_char)
}

config_shadowsocks() {
    if [ "${selected}" == "1" ]; then
        local server_value="\"0.0.0.0\""
        if get_ipv6; then
            server_value="[\"[::0]\",\"0.0.0.0\"]"
        fi

        if [ ! -d "$(dirname ${shadowsocks_libev_config})" ]; then
            mkdir -p $(dirname ${shadowsocks_libev_config})
        fi

        cat >${shadowsocks_libev_config} <<-EOF
{
    "server":${server_value},
    "server_port":${shadowsocksport},
    "password":"${shadowsockspwd}",
    "method":"${shadowsockscipher}",
    "timeout":300,
    "user":"nobody",
    "fast_open":false,
    "mode": "${shadowsocksudp}"
}
EOF

    elif [ "${selected}" == "2" ]; then
        if [ ! -d "$(dirname ${shadowsocks_r_config})" ]; then
            mkdir -p $(dirname ${shadowsocks_r_config})
        fi
        cat >${shadowsocks_r_config} <<-EOF
{
    "server":"0.0.0.0",
    "server_ipv6":"::",
    "server_port":${shadowsocksport},
    "local_address":"127.0.0.1",
    "local_port":1080,
    "password":"${shadowsockspwd}",
    "method":"${shadowsockscipher}",
    "protocol":"${shadowsockprotocol}",
    "protocol_param":"",
    "obfs":"${shadowsockobfs}",
    "obfs_param":"",
    "timeout":120,
    "redirect":"",
    "dns_ipv6":false,
    "fast_open":false
}
EOF
    elif [ "${selected}" == "3" ]; then
        # shadowsocks-rust config
        local server_value="\"0.0.0.0\""
        if get_ipv6; then
            # For rust, single string "::" is commonly used
            server_value="\"::\""
        fi

        if [ ! -d "${shadowsocks_rust_dir}" ]; then
            mkdir -p "${shadowsocks_rust_dir}"
        fi

        cat >${shadowsocks_rust_config} <<-EOF
{
    "server": ${server_value},
    "server_port": ${shadowsocksport},
    "password": "${shadowsockspwd}",
    "method": "${shadowsockscipher}",
    "mode": "${shadowsocksudp}"
}
EOF
    fi
}

download() {
    local filename=$(basename $1)
    if [ -f ${1} ]; then
        echo "${filename} [found]"
    else
        echo "${filename} not found, download now..."
        wget --no-check-certificate -c -t3 -T60 -O ${1} ${2} >/dev/null 2>&1
        if [ $? -ne 0 ]; then
            echo -e "[${red}Error${plain}] Download ${filename} failed."
            exit 1
        fi
    fi
}

download_files() {
    echo
    cd ${cur_dir} || exit
    if [ "${selected}" == "1" ]; then
        get_libev_ver
        shadowsocks_libev_file="shadowsocks-libev-$(echo ${libev_ver} | sed -e 's/^[a-zA-Z]//g')"
        shadowsocks_libev_url="https://github.com/shadowsocks/shadowsocks-libev/releases/download/${libev_ver}/${shadowsocks_libev_file}.tar.gz"

        download "${shadowsocks_libev_file}.tar.gz" "${shadowsocks_libev_url}"
        if check_sys packageManager yum; then
            download "${shadowsocks_libev_init}" "${shadowsocks_libev_centos}"
        elif check_sys packageManager apt; then
            download "${shadowsocks_libev_init}" "${shadowsocks_libev_debian}"
        fi
    elif [ "${selected}" == "2" ]; then
        download "${shadowsocks_r_file}.tar.gz" "${shadowsocks_r_url}"
        if check_sys packageManager yum; then
            download "${shadowsocks_r_init}" "${shadowsocks_r_centos}"
        elif check_sys packageManager apt; then
            download "${shadowsocks_r_init}" "${shadowsocks_r_debian}"
        fi
    elif [ "${selected}" == "3" ]; then
        download_rust_binaries
    fi
}

config_firewall() {
    if centosversion 6; then
        /etc/init.d/iptables status >/dev/null 2>&1
        if [ $? -eq 0 ]; then
            iptables -L -n | grep -i ${shadowsocksport} >/dev/null 2>&1
            if [ $? -ne 0 ]; then
                iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${shadowsocksport} -j ACCEPT
                iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${shadowsocksport} -j ACCEPT
                /etc/init.d/iptables save
                /etc/init.d/iptables restart
            else
                echo
                echo -e "[${green}Info${plain}] port ${green}${shadowsocksport}${plain} already be enabled."
            fi
        else
            echo -e "[${yellow}Warning${plain}] iptables looks like not running or not installed, please enable port ${shadowsocksport} manually if necessary."
        fi
    elif centosversion 7; then
        systemctl status firewalld >/dev/null 2>&1
        if [ $? -eq 0 ]; then
            default_zone=$(firewall-cmd --get-default-zone)
            firewall-cmd --permanent --zone=${default_zone} --add-port=${shadowsocksport}/tcp
            firewall-cmd --permanent --zone=${default_zone} --add-port=${shadowsocksport}/udp
            firewall-cmd --reload
        else
            echo -e "[${yellow}Warning${plain}] firewalld looks like not running or not installed, please enable port ${shadowsocksport} manually if necessary."
        fi
    fi
}

install_libsodium() {
    if [ -f /usr/lib/libsodium.a ] || [ -f /usr/lib64/libsodium.a ]; then
        echo
        echo -e "[${green}Info${plain}] ${libsodium_file} already installed."
    else
        echo
        echo -e "[${green}Info${plain}] ${libsodium_file} start installing."
        cd ${cur_dir} || exit
        download "${libsodium_file}.tar.gz" "${libsodium_url}"
        tar zxf ${libsodium_file}.tar.gz
        cd ${libsodium_file} || exit
        ./configure --prefix=/usr && make && make install
        if [ $? -ne 0 ]; then
            echo -e "[${red}Error${plain}] ${libsodium_file} install failed."
            install_cleanup
            exit 1
        fi
        echo -e "[${green}Info${plain}] ${libsodium_file} install success!"
    fi
}

install_mbedtls() {
    if [ -f /usr/lib/libmbedtls.a ] || [ -f /usr/lib64/libmbedtls.a ]; then
        echo
        echo -e "[${green}Info${plain}] ${mbedtls_file} already installed."
    else
        echo
        echo -e "[${green}Info${plain}] ${mbedtls_file} start installing."
        cd ${cur_dir} || exit
        download "mbedtls-${mbedtls_file}.tar.gz" "${mbedtls_url}"
        tar zxf mbedtls-${mbedtls_file}.tar.gz
        cd mbedtls-${mbedtls_file}
        make SHARED=1 CFLAGS=-fPIC
        make DESTDIR=/usr install
        if [ $? -ne 0 ]; then
            echo -e "[${red}Error${plain}] ${mbedtls_file} install failed."
            install_cleanup
            exit 1
        fi
        echo -e "[${green}Info${plain}] ${mbedtls_file} install success!"
    fi
}

# Download and install ssserver binary from shadowsocks-rust releases
download_rust_binaries() {
    echo -e "[${green}Info${plain}] Fetching latest shadowsocks-rust release info..."
    local arch=$(uname -m)
    local arch_pat="x86_64"
    case "$arch" in
        x86_64) arch_pat="x86_64";;
        aarch64) arch_pat="aarch64";;
        armv7l|armv7) arch_pat="armv7";;
        i386|i686) arch_pat="i686";;
        *) arch_pat="x86_64";;
    esac
    # Try to prefer musl for compatibility, fallback to gnu
    rust_asset_url=$(wget --no-check-certificate -qO- "${ssrust_latest_api}" \
        | grep -o '"browser_download_url": *"[^"]\+"' \
        | cut -d '"' -f 4 \
        | grep -E "linux" \
        | grep -E "${arch_pat}" \
        | grep -E '\\.tar\\.xz$' \
        | grep -E 'musl|gnu' \
        | head -n 1)

    if [ -z "$rust_asset_url" ]; then
        rust_asset_url=$(wget --no-check-certificate -qO- "${ssrust_latest_api}" \
            | grep -o '"browser_download_url": *"[^"]\+"' \
            | cut -d '"' -f 4 \
            | grep -E "linux" \
            | grep -E '\\.tar\\.xz$' \
            | head -n 1)
    fi

    if [ -z "$rust_asset_url" ]; then
        echo -e "[${red}Error${plain}] Failed to determine shadowsocks-rust binary download URL."
        exit 1
    fi

    local rust_pkg=$(basename "$rust_asset_url")
    echo -e "[${green}Info${plain}] Downloading ${rust_pkg}..."
    download "$rust_pkg" "$rust_asset_url"

    echo -e "[${green}Info${plain}] Extracting ${rust_pkg}..."
    tar -xJf "$rust_pkg"

    # Find ssserver in extracted folder
    local unpack_dir=$(tar -tf "$rust_pkg" | head -1 | cut -d/ -f1)
    if [ -z "$unpack_dir" ]; then
        echo -e "[${red}Error${plain}] Failed to extract shadowsocks-rust package."
        exit 1
    fi

    # Install binaries
    if [ -f "${unpack_dir}/ssserver" ]; then
        install -m 755 "${unpack_dir}/ssserver" /usr/local/bin/ssserver
    elif [ -f "${unpack_dir}/bin/ssserver" ]; then
        install -m 755 "${unpack_dir}/bin/ssserver" /usr/local/bin/ssserver
    else
        # Try locating anywhere
        local ssserver_path=$(find "${unpack_dir}" -type f -name ssserver | head -n 1)
        if [ -n "$ssserver_path" ]; then
            install -m 755 "$ssserver_path" /usr/local/bin/ssserver
        else
            echo -e "[${red}Error${plain}] ssserver binary not found in the package."
            exit 1
        fi
    fi

    # Optionally install ssurl for QR helpers
    local ssurl_path=""
    if [ -f "${unpack_dir}/ssurl" ]; then
        ssurl_path="${unpack_dir}/ssurl"
    elif [ -f "${unpack_dir}/bin/ssurl" ]; then
        ssurl_path="${unpack_dir}/bin/ssurl"
    else
        ssurl_path=$(find "${unpack_dir}" -type f -name ssurl | head -n 1)
    fi
    if [ -n "$ssurl_path" ]; then
        install -m 755 "$ssurl_path" /usr/local/bin/ssurl || true
    fi
}

install_shadowsocks_rust() {
    if [ -f /usr/local/bin/ssserver ]; then
        echo
        echo -e "[${green}Info${plain}] ${software[2]} already installed."
    else
        echo
        echo -e "[${green}Info${plain}] ${software[2]} start installing."
        cd ${cur_dir} || exit
        download_rust_binaries
    fi

    # Setup service (prefer systemd)
    if command -v systemctl >/dev/null 2>&1; then
        cat >"${shadowsocks_rust_systemd}" <<-EOF
[Unit]
Description=Shadowsocks-Rust Server (ssserver)
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=nobody
AmbientCapabilities=CAP_NET_BIND_SERVICE
ExecStart=/usr/local/bin/ssserver -c ${shadowsocks_rust_config} -a nobody
Restart=on-failure
RestartSec=3s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable ssserver >/dev/null 2>&1 || true
    else
        # SysV init script: copy from repo scripts/ if available, otherwise fallback to heredoc
        if [ -f "${cur_dir}/scripts/shadowsocks-rust" ]; then
            install -m 755 "${cur_dir}/scripts/shadowsocks-rust" "${shadowsocks_rust_init}"
        else
            cat >"${shadowsocks_rust_init}" <<-'EOF'
#!/bin/sh
### BEGIN INIT INFO
# Provides:          shadowsocks-rust
# Required-Start:    $network $local_fs
# Required-Stop:     $network $local_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Shadowsocks-Rust Server
### END INIT INFO
# chkconfig: 2345 20 80
# description: Shadowsocks-Rust Server

NAME=ssserver
DAEMON=/usr/local/bin/ssserver
CONF=/etc/shadowsocks-rust/config.json
PIDFILE=/var/run/ssserver.pid
LOGFILE=/var/log/ssserver.log
USER=nobody

start() {
    echo -n "Starting $NAME: "
    nohup "$DAEMON" -c "$CONF" -a "$USER" >>"$LOGFILE" 2>&1 &
    echo $! > "$PIDFILE"
    echo "done."
}

stop() {
    echo -n "Stopping $NAME: "
    if [ -f "$PIDFILE" ]; then
        kill $(cat "$PIDFILE") 2>/dev/null || true
        rm -f "$PIDFILE"
    else
        pkill -f "$DAEMON" 2>/dev/null || true
    fi
    echo "done."
}

restart() {
    stop
    sleep 1
    start
}

status() {
    if [ -f "$PIDFILE" ] && ps -p $(cat "$PIDFILE") >/dev/null 2>&1; then
        echo "$NAME is running (pid $(cat \"$PIDFILE\"))"
        exit 0
    fi
    pgrep -f "$DAEMON" >/dev/null 2>&1 && { echo "$NAME is running"; exit 0; }
    echo "$NAME is stopped"
    exit 3
}

case "$1" in
    start) start ;;
    stop) stop ;;
    restart) restart ;;
    status) status ;;
    *) echo "Usage: $0 {start|stop|restart|status}" ; exit 1 ;;
esac
exit 0
EOF
            chmod +x "${shadowsocks_rust_init}"
        fi
        local service_name=$(basename ${shadowsocks_rust_init})
        if check_sys packageManager yum; then
            chkconfig --add ${service_name}
            chkconfig ${service_name} on
        elif check_sys packageManager apt; then
            update-rc.d -f ${service_name} defaults
        fi
    fi
}

install_completed_rust() {
    clear
    if command -v systemctl >/dev/null 2>&1; then
        systemctl start ssserver
    else
        ${shadowsocks_rust_init} start
    fi
    echo
    echo -e "Congratulations, ${green}${software[2]}${plain} server install completed!"
    echo -e "Your Server IP        : ${red} $(get_ip) ${plain}"
    echo -e "Your Server Port      : ${red} ${shadowsocksport} ${plain}"
    echo -e "Your Password         : ${red} ${shadowsockspwd} ${plain}"
    echo -e "Your Encryption Method: ${red} ${shadowsockscipher} ${plain}"
    echo -e "Your Config File      : ${red} ${shadowsocks_rust_config} ${plain}"
}

install_shadowsocks_libev() {
    if [ -f /usr/local/bin/ss-server ] || [ -f /usr/bin/ss-server ]; then
        echo
        echo -e "[${green}Info${plain}] ${software[0]} already installed."
    else
        echo
        echo -e "[${green}Info${plain}] ${software[0]} start installing."
        cd ${cur_dir} || exit
        tar zxf ${shadowsocks_libev_file}.tar.gz
        cd ${shadowsocks_libev_file} || exit
        ./configure --disable-documentation && make && make install
        if [ $? -eq 0 ]; then
            chmod +x ${shadowsocks_libev_init}
            local service_name=$(basename ${shadowsocks_libev_init})
            if check_sys packageManager yum; then
                chkconfig --add ${service_name}
                chkconfig ${service_name} on
            elif check_sys packageManager apt; then
                update-rc.d -f ${service_name} defaults
            fi
        else
            echo
            echo -e "[${red}Error${plain}] ${software[0]} install failed."
            install_cleanup
            exit 1
        fi
    fi
}

install_shadowsocks_r() {
    if [ -f /usr/local/shadowsocks/server.py ]; then
        echo
        echo -e "[${green}Info${plain}] ${software[1]} already installed."
    else
        echo
        echo -e "[${green}Info${plain}] ${software[1]} start installing."
        cd ${cur_dir} || exit
        tar zxf ${shadowsocks_r_file}.tar.gz
        mv ${shadowsocks_r_file}/shadowsocks /usr/local/
        if [ -f /usr/local/shadowsocks/server.py ]; then
            chmod +x ${shadowsocks_r_init}
            local service_name=$(basename ${shadowsocks_r_init})
            if check_sys packageManager yum; then
                chkconfig --add ${service_name}
                chkconfig ${service_name} on
            elif check_sys packageManager apt; then
                update-rc.d -f ${service_name} defaults
            fi
        else
            echo
            echo -e "[${red}Error${plain}] ${software[1]} install failed."
            install_cleanup
            exit 1
        fi
    fi
}

install_completed_libev() {
    clear
    ldconfig
    ${shadowsocks_libev_init} start
    echo
    echo -e "Congratulations, ${green}${software[0]}${plain} server install completed!"
    echo -e "Your Server IP        : ${red} $(get_ip) ${plain}"
    echo -e "Your Server Port      : ${red} ${shadowsocksport} ${plain}"
    echo -e "Your Password         : ${red} ${shadowsockspwd} ${plain}"
    echo -e "Your Encryption Method: ${red} ${shadowsockscipher} ${plain}"
    echo -e "Your Config File      : ${red} ${shadowsocks_libev_config} ${plain}"
}

install_completed_r() {
    clear
    ${shadowsocks_r_init} start
    echo
    echo -e "Congratulations, ${green}${software[1]}${plain} server install completed!"
    echo -e "Your Server IP        : ${red} $(get_ip) ${plain}"
    echo -e "Your Server Port      : ${red} ${shadowsocksport} ${plain}"
    echo -e "Your Password         : ${red} ${shadowsockspwd} ${plain}"
    echo -e "Your Protocol         : ${red} ${shadowsockprotocol} ${plain}"
    echo -e "Your obfs             : ${red} ${shadowsockobfs} ${plain}"
    echo -e "Your Encryption Method: ${red} ${shadowsockscipher} ${plain}"
    echo -e "Your Config File      : ${red} ${shadowsocks_r_config} ${plain}"
}

qr_generate_libev() {
    if [ "$(command -v qrencode)" ]; then
        local tmp=$(echo -n "${shadowsockscipher}:${shadowsockspwd}@$(get_ip):${shadowsocksport}" | base64 -w0)
        local qr_code="ss://${tmp}"
        echo
        echo "Your QR Code: (For Shadowsocks Windows, OSX, Android and iOS clients)"
        echo -e "${green} ${qr_code} ${plain}"
        echo -n "${qr_code}" | qrencode -s8 -o ${cur_dir}/shadowsocks_libev_qr.png
        echo "Your QR Code has been saved as a PNG file path:"
        echo -e "${green} ${cur_dir}/shadowsocks_libev_qr.png ${plain}"
    fi
}

qr_generate_r() {
    if [ "$(command -v qrencode)" ]; then
        local tmp1=$(echo -n "${shadowsockspwd}" | base64 -w0 | sed 's/=//g;s/\//_/g;s/+/-/g')
        local tmp2=$(echo -n "$(get_ip):${shadowsocksport}:${shadowsockprotocol}:${shadowsockscipher}:${shadowsockobfs}:${tmp1}/?obfsparam=" | base64 -w0)
        local qr_code="ssr://${tmp2}"
        echo
        echo "Your QR Code: (For ShadowsocksR Windows, Android clients only)"
        echo -e "${green} ${qr_code} ${plain}"
        echo -n "${qr_code}" | qrencode -s8 -o ${cur_dir}/shadowsocks_r_qr.png
        echo "Your QR Code has been saved as a PNG file path:"
        echo -e "${green} ${cur_dir}/shadowsocks_r_qr.png ${plain}"
    fi
}

qr_generate_rust() {
    # Use ssurl if available for a proper SIP002 url; otherwise, fallback to basic base64 (method:password@host:port)
    if [ -x /usr/local/bin/ssurl ] && [ -f "${shadowsocks_rust_config}" ]; then
        local encoded=$(ssurl -e "${shadowsocks_rust_config}" 2>/dev/null | head -n 1)
        if [ -n "$encoded" ] && [ "$(command -v qrencode)" ]; then
            echo
            echo "Your QR Code: (For Shadowsocks clients)"
            echo -e "${green} ${encoded} ${plain}"
            echo -n "$encoded" | qrencode -s8 -o ${cur_dir}/shadowsocks_rust_qr.png
            echo "Your QR Code has been saved as a PNG file path:"
            echo -e "${green} ${cur_dir}/shadowsocks_rust_qr.png ${plain}"
        fi
    else
        if [ "$(command -v qrencode)" ]; then
            local tmp=$(echo -n "${shadowsockscipher}:${shadowsockspwd}@$(get_ip):${shadowsocksport}" | base64 -w0)
            local qr_code="ss://${tmp}"
            echo
            echo "Your QR Code: (For Shadowsocks clients)"
            echo -e "${green} ${qr_code} ${plain}"
            echo -n "${qr_code}" | qrencode -s8 -o ${cur_dir}/shadowsocks_rust_qr.png
            echo "Your QR Code has been saved as a PNG file path:"
            echo -e "${green} ${cur_dir}/shadowsocks_rust_qr.png ${plain}"
        fi
    fi
}

install_main() {
    install_libsodium
    if ! ldconfig -p | grep -wq "/usr/lib"; then
        echo "/usr/lib" >/etc/ld.so.conf.d/lib.conf
    fi
    if ! ldconfig -p | grep -wq "/usr/lib64"; then
        echo "/usr/lib64" >>/etc/ld.so.conf.d/lib.conf
    fi
    ldconfig

    if [ "${selected}" == "1" ]; then
        install_mbedtls
        ldconfig
        install_shadowsocks_libev
        install_completed_libev
        qr_generate_libev
    elif [ "${selected}" == "2" ]; then
        install_shadowsocks_r
        install_completed_r
        qr_generate_r
    elif [ "${selected}" == "3" ]; then
        install_shadowsocks_rust
        install_completed_rust
        qr_generate_rust
    fi

    echo
    echo "Enjoy it!"
    echo
}

install_cleanup() {
    cd ${cur_dir} || exit
    rm -rf ${libsodium_file} ${libsodium_file}.tar.gz
    rm -rf mbedtls-${mbedtls_file} mbedtls-${mbedtls_file}.tar.gz
    rm -rf ${shadowsocks_libev_file} ${shadowsocks_libev_file}.tar.gz
    rm -rf ${shadowsocks_r_file} ${shadowsocks_r_file}.tar.gz
    # rust tarballs usually named like shadowsocks-<ver>-stable.<triple>.tar.xz
    rm -rf shadowsocks-*.tar.xz shadowsocks-*-linux-*.tar.xz 2>/dev/null || true
}

install_shadowsocks() {
    disable_selinux
    install_select
    install_dependencies
    install_prepare
    config_shadowsocks
    download_files
    if check_sys packageManager yum; then
        config_firewall
    fi
    install_main
    install_cleanup
}

uninstall_libsodium() {
    printf "Are you sure uninstall ${red}${libsodium_file}${plain}? [y/n]\n"
    read -p "(default: n):" answer
    [ -z ${answer} ] && answer="n"
    if [ "${answer}" == "y" ] || [ "${answer}" == "Y" ]; then
        rm -f /usr/lib64/libsodium.so.23
        rm -f /usr/lib64/libsodium.a
        rm -f /usr/lib64/libsodium.la
        rm -f /usr/lib64/pkgconfig/libsodium.pc
        rm -f /usr/lib64/libsodium.so.23.3.0
        rm -f /usr/lib64/libsodium.so
        rm -rf /usr/include/sodium
        rm -f /usr/include/sodium.h
        ldconfig
        echo -e "[${green}Info${plain}] ${libsodium_file} uninstall success"
    else
        echo
        echo -e "[${green}Info${plain}] ${libsodium_file} uninstall cancelled, nothing to do..."
        echo
    fi
}

uninstall_mbedtls() {
    printf "Are you sure uninstall ${red}${mbedtls_file}${plain}? [y/n]\n"
    read -p "(default: n):" answer
    [ -z ${answer} ] && answer="n"
    if [ "${answer}" == "y" ] || [ "${answer}" == "Y" ]; then
        rm -f /usr/lib/libmbedtls.a
        rm -f /usr/lib/libmbedtls.so
        rm -f /usr/lib/libmbedtls.so.13
        rm -rf /usr/include/mbedtls
        rm -f /usr/include/mbedtls/mbedtls_config.h
        rm -f /usr/bin/mbedtls_*
        ldconfig
        echo -e "[${green}Info${plain}] ${mbedtls_file} uninstall success"
    else
        echo
        echo -e "[${green}Info${plain}] ${mbedtls_file} uninstall cancelled, nothing to do..."
        echo
    fi
}

uninstall_shadowsocks_libev() {
    printf "Are you sure uninstall ${red}${software[0]}${plain}? [y/n]\n"
    read -p "(default: n):" answer
    [ -z ${answer} ] && answer="n"
    if [ "${answer}" == "y" ] || [ "${answer}" == "Y" ]; then
        ${shadowsocks_libev_init} status >/dev/null 2>&1
        if [ $? -eq 0 ]; then
            ${shadowsocks_libev_init} stop
        fi
        local service_name=$(basename ${shadowsocks_libev_init})
        if check_sys packageManager yum; then
            chkconfig --del ${service_name}
        elif check_sys packageManager apt; then
            update-rc.d -f ${service_name} remove
        fi
        rm -f /usr/local/bin/ss-local
        rm -f /usr/local/bin/ss-server
        rm -f /usr/local/bin/ss-tunnel
        rm -f /usr/local/bin/ss-manager
        rm -f /usr/local/bin/ss-redir
        rm -f /usr/local/bin/ss-nat
        rm -f /usr/local/include/shadowsocks.h
        rm -f /usr/local/lib/libshadowsocks-libev.a
        rm -f /usr/local/lib/libshadowsocks-libev.la
        rm -f /usr/local/lib/pkgconfig/shadowsocks-libev.pc
        rm -f /usr/local/share/man/man1/ss-local.1
        rm -f /usr/local/share/man/man1/ss-server.1
        rm -f /usr/local/share/man/man1/ss-tunnel.1
        rm -f /usr/local/share/man/man1/ss-manager.1
        rm -f /usr/local/share/man/man1/ss-redir.1
        rm -f /usr/local/share/man/man1/ss-nat.1
        rm -f /usr/local/share/man/man8/shadowsocks-libev.8
        rm -rf /usr/local/share/doc/shadowsocks-libev
        rm -rf $(dirname ${shadowsocks_libev_config})
        rm -f ${shadowsocks_libev_init}
        echo -e "[${green}Info${plain}] ${software[0]} uninstall success"
    else
        echo
        echo -e "[${green}Info${plain}] ${software[0]} uninstall cancelled, nothing to do..."
        echo
    fi
}

uninstall_shadowsocks_r() {
    printf "Are you sure uninstall ${red}${software[1]}${plain}? [y/n]\n"
    read -p "(default: n):" answer
    [ -z ${answer} ] && answer="n"
    if [ "${answer}" == "y" ] || [ "${answer}" == "Y" ]; then
        ${shadowsocks_r_init} status >/dev/null 2>&1
        if [ $? -eq 0 ]; then
            ${shadowsocks_r_init} stop
        fi
        local service_name=$(basename ${shadowsocks_r_init})
        if check_sys packageManager yum; then
            chkconfig --del ${service_name}
        elif check_sys packageManager apt; then
            update-rc.d -f ${service_name} remove
        fi
        rm -fr $(dirname ${shadowsocks_r_config})
        rm -f ${shadowsocks_r_init}
        rm -f /var/log/shadowsocks.log
        rm -fr /usr/local/shadowsocks
        echo -e "[${green}Info${plain}] ${software[1]} uninstall success"
    else
        echo
        echo -e "[${green}Info${plain}] ${software[1]} uninstall cancelled, nothing to do..."
        echo
    fi
}

uninstall_shadowsocks() {
    while true; do
        echo "Which Shadowsocks server you want to uninstall?"
        for ((i = 1; i <= ${#software[@]}; i++)); do
            hint="${software[$i - 1]}"
            echo -e "${green}${i}${plain}) ${hint}"
        done
        read -p "Please enter a number [1-3]:" un_select
        case "${un_select}" in
        1 | 2 | 3)
            echo
            echo "You choose = ${software[${un_select} - 1]}"
            echo
            break
            ;;
        *)
            echo -e "[${red}Error${plain}] Please only enter a number [1-3]"
            ;;
        esac
    done

    if [ "${un_select}" == "1" ]; then
        if [ -f ${shadowsocks_libev_init} ]; then
            uninstall_shadowsocks_libev
        else
            echo -e "[${red}Error${plain}] ${software[${un_select} - 1]} not installed, please check it and try again."
            echo
            exit 1
        fi
    elif [ "${un_select}" == "2" ]; then
        if [ -f ${shadowsocks_r_init} ]; then
            uninstall_shadowsocks_r
        else
            echo -e "[${red}Error${plain}] ${software[${un_select} - 1]} not installed, please check it and try again."
            echo
            exit 1
        fi
    elif [ "${un_select}" == "3" ]; then
        uninstall_shadowsocks_rust
        fi
    fi
    ldconfig
}

upgrade_shadowsocks() {
    clear
    echo -e "Upgrade ${green}${software[0]}${plain} ? [y/n]"
    read -p "(default: n) : " answer_upgrade
    [ -z ${answer_upgrade} ] && answer_upgrade="n"
    if [ "${answer_upgrade}" == "Y" ] || [ "${answer_upgrade}" == "y" ]; then
        if [ -f ${shadowsocks_r_init} ]; then
            echo
            echo -e "[${red}Error${plain}] Only support shadowsocks-libev !"
            echo
            exit 1
        elif [ -f ${shadowsocks_libev_init} ]; then
            if [ ! "$(command -v ss-server)" ]; then
                echo
                echo -e "[${red}Error${plain}] Shadowsocks-libev not installed..."
                echo
                exit 1
            else
                current_local_version=$(ss-server --help | grep shadowsocks | cut -d' ' -f2)
            fi
            get_libev_ver
            current_libev_ver=$(echo ${libev_ver} | sed -e 's/^[a-zA-Z]//g')
            echo
            echo -e "[${green}Info${plain}] Shadowsocks-libev Version: v${current_local_version}"
            if [[ "${current_libev_ver}" == "${current_local_version}" ]]; then
                echo
                echo -e "[${green}Info${plain}] Already updated to latest version !"
                echo
                exit 1
            fi
            uninstall_shadowsocks_libev
            ldconfig
            if [ "${answer}" == "Y" ] || [ "${answer}" == "y" ]; then
                disable_selinux
                selected=1
                echo
                echo "You will upgrade ${software[${seleted} - 1]}"
                echo
                shadowsockspwd=$(cat /etc/shadowsocks-libev/config.json | grep password | cut -d\" -f4)
                shadowsocksport=$(cat /etc/shadowsocks-libev/config.json | grep server_port | cut -d ',' -f1 | cut -d ':' -f2)
                shadowsockscipher=$(cat /etc/shadowsocks-libev/config.json | grep method | cut -d\" -f4)
                config_shadowsocks
                download_files
                install_shadowsocks_libev
                install_completed_libev
                qr_generate_libev
            else
                exit 1
            fi
        else
            echo
            echo -e "[${red}Error${plain}] Shadowsocks-libev server doesn't exist !"
            echo
            exit 1
        fi
    else
        echo
        echo -e "[${green}Info${plain}] ${software[0]} upgrade cancelled, nothing to do..."
        echo
    fi
}

uninstall_shadowsocks_rust() {
    printf "Are you sure uninstall ${red}${software[2]}${plain}? [y/n]\n"
    read -p "(default: n):" answer
    [ -z ${answer} ] && answer="n"
    if [ "${answer}" == "y" ] || [ "${answer}" == "Y" ]; then
        if command -v systemctl >/dev/null 2>&1; then
            systemctl stop ssserver 2>/dev/null || true
            systemctl disable ssserver 2>/dev/null || true
            rm -f "${shadowsocks_rust_systemd}"
            systemctl daemon-reload 2>/dev/null || true
        else
            if [ -f "${shadowsocks_rust_init}" ]; then
                ${shadowsocks_rust_init} stop 2>/dev/null || true
                local service_name=$(basename ${shadowsocks_rust_init})
                if check_sys packageManager yum; then
                    chkconfig --del ${service_name} 2>/dev/null || true
                elif check_sys packageManager apt; then
                    update-rc.d -f ${service_name} remove 2>/dev/null || true
                fi
                rm -f "${shadowsocks_rust_init}"
            fi
        fi
        rm -f /usr/local/bin/ssserver /usr/local/bin/ssurl 2>/dev/null || true
        rm -rf "${shadowsocks_rust_dir}" 2>/dev/null || true
        rm -f /var/log/ssserver.log 2>/dev/null || true
        echo -e "[${green}Info${plain}] ${software[2]} uninstall success"
    else
        echo
        echo -e "[${green}Info${plain}] ${software[2]} uninstall cancelled, nothing to do..."
        echo
    fi
}

# Initialization step
action=$1
[ -z $1 ] && action=install
case "${action}" in
install | uninstall | upgrade)
    ${action}_shadowsocks
    ;;
*)
    echo "Arguments error! [${action}]"
    echo "Usage: $(basename $0) [install|uninstall|upgrade]"
    ;;
esac
