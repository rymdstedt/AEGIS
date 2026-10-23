"""Deterministic infrastructure and server-product fingerprint registry.

The registry converts concrete banner, title, header, cookie-name, CPE-adjacent,
or management-page signatures into structured product identities.  It never
uses an LLM and never emits arbitrary surrounding page content.  Database
aliases are kept separate from display names because vulnerability indexes
often use CPE-style product names such as ``vcenter_server`` or ``pve-manager``.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]+")
_SAFE_VERSION = re.compile(r"[0-9A-Za-z][0-9A-Za-z._()+-]{0,79}")


@dataclass(frozen=True)
class ProductFingerprintRule:
    key: str
    category: str
    vendor: str
    product: str
    search_vendor: str
    search_product: str
    patterns: tuple[str, ...]
    version_patterns: tuple[str, ...] = ()
    confidence: str = "high"
    priority: int = 50
    allow_body: bool = False
    cve_searchable: bool = True
    version_caveat: str = ""


def _rule(
    key: str,
    category: str,
    vendor: str,
    product: str,
    search_vendor: str,
    search_product: str,
    *patterns: str,
    version_patterns: tuple[str, ...] = (),
    confidence: str = "high",
    priority: int = 50,
    allow_body: bool = False,
    cve_searchable: bool = True,
    version_caveat: str = "",
) -> ProductFingerprintRule:
    return ProductFingerprintRule(
        key=key,
        category=category,
        vendor=vendor,
        product=product,
        search_vendor=search_vendor,
        search_product=search_product,
        patterns=patterns,
        version_patterns=version_patterns,
        confidence=confidence,
        priority=priority,
        allow_body=allow_body,
        cve_searchable=cve_searchable,
        version_caveat=version_caveat,
    )


PRODUCT_FINGERPRINT_RULES: tuple[ProductFingerprintRule, ...] = (
    # Hypervisors and virtualization control planes.
    _rule(
        "vmware-vcenter", "hypervisor_management", "VMware", "VMware vCenter Server",
        "vmware", "vcenter_server",
        r"\bVMware\s+vCenter(?:\s+Server)?\b", r"\bvSphere\s+(?:Web\s+)?Client\b",
        version_patterns=(
            r"(?i)\b(?:VMware\s+)?vCenter(?:\s+Server)?[/\s:,-]+(?:version\s*)?(?P<version>\d+(?:\.\d+){1,3}(?:[-.]\d+)?)",
            r"(?i)\bX-VMWARE-VCENTER-VERSION\s*[:=]\s*(?P<version>[0-9A-Za-z._()+-]+)",
        ), priority=130, allow_body=True,
    ),
    _rule(
        "vmware-esxi", "hypervisor", "VMware", "VMware ESXi", "vmware", "esxi",
        r"\bVMware\s+ESXi\b", r"\bVMware\s+ESX\s+Server\b",
        version_patterns=(
            r"(?i)\bVMware\s+ESXi(?:\s+Software)?[/\s:,-]+(?:version\s*)?(?P<version>\d+(?:\.\d+){1,3}(?:[-.]\d+)?)",
            r"(?i)\bESXi[-_/ ](?P<version>\d+(?:\.\d+){1,3}(?:[-.]\d+)?)",
        ), priority=129, allow_body=True,
    ),
    _rule(
        "proxmox-ve", "hypervisor_management", "Proxmox", "Proxmox Virtual Environment",
        "proxmox", "pve-manager",
        r"\bProxmox\s+Virtual\s+Environment\b", r"\bPVE\s+Manager\b",
        r"\bPVEAuthCookie\b", r"\bpve2-api-daemon\b",
        version_patterns=(
            r"(?i)\bpve-manager[/\s:=-]+(?P<version>\d+(?:\.\d+){1,3}(?:[-.]\d+)?)",
            r"(?i)\bProxmox(?:\s+VE|\s+Virtual\s+Environment)?[/\s:=-]+(?P<version>\d+(?:\.\d+){1,3})",
        ), priority=128, allow_body=True,
    ),
    _rule(
        "microsoft-hyper-v", "hypervisor", "Microsoft", "Windows Hyper-V",
        "microsoft", "windows hyper-v",
        r"\bMicrosoft\s+Hyper-V\b", r"\bWindows\s+Hyper-V\b", r"\bHyper-V\s+Server\b",
        version_patterns=(
            r"(?i)\bHyper-V\s+Server\s+(?P<version>20\d{2})\b",
            r"(?i)\bMicrosoft\s+Hyper-V[/\s:=-]+(?P<version>\d+(?:\.\d+){1,3})",
        ), priority=127, allow_body=True,
    ),
    _rule(
        "nutanix-prism-central", "hypervisor_management", "Nutanix", "Prism Central",
        "nutanix", "prism central",
        r"\bNutanix\s+Prism\s+Central\b", r"\bPrism\s+Central\b", r"\bNTNX_IGW_SESSION\b",
        version_patterns=(
            r"(?i)\b(?:Nutanix\s+)?Prism\s+Central[/\s:=-]+(?P<version>[A-Za-z0-9][0-9A-Za-z._+-]+)",
        ), priority=126, allow_body=True,
    ),
    _rule(
        "xcp-ng", "hypervisor", "Vates", "XCP-ng", "vates", "xcp-ng",
        r"\bXCP-ng\b", r"\bXCP-ng\s+Center\b",
        version_patterns=(r"(?i)\bXCP-ng[/\s:=-]+(?P<version>\d+(?:\.\d+){1,3})",),
        priority=125, allow_body=True,
    ),
    _rule(
        "citrix-xenserver", "hypervisor", "Citrix", "XenServer", "citrix", "xenserver",
        r"\bCitrix\s+Hypervisor\b", r"\bCitrix\s+XenServer\b", r"\bXenServer\b",
        version_patterns=(
            r"(?i)\b(?:Citrix\s+)?(?:Hypervisor|XenServer)[/\s:=-]+(?P<version>\d+(?:\.\d+){1,3})",
        ), priority=124, allow_body=True,
    ),
    _rule(
        "openstack-horizon", "cloud_management", "OpenStack", "Horizon",
        "openstack", "horizon",
        r"\bOpenStack\s+(?:Dashboard|Horizon)\b", r"\bHorizon\s+OpenStack\s+Dashboard\b",
        version_patterns=(r"(?i)\bOpenStack\s+Horizon[/\s:=-]+(?P<version>[0-9A-Za-z._+-]+)",),
        priority=115, allow_body=True,
    ),
    _rule(
        "ovirt-engine", "hypervisor_management", "oVirt", "oVirt Engine",
        "ovirt", "ovirt-engine", r"\boVirt\s+Engine\b", r"\boVirt\s+Administration\s+Portal\b",
        version_patterns=(r"(?i)\boVirt(?:\s+Engine)?[/\s:=-]+(?P<version>\d+(?:\.\d+){1,4})",),
        priority=114, allow_body=True,
    ),
    _rule(
        "redhat-virtualization", "hypervisor_management", "Red Hat", "Virtualization",
        "redhat", "virtualization", r"\bRed\s+Hat\s+Virtualization(?:\s+Manager)?\b",
        version_patterns=(r"(?i)\bRed\s+Hat\s+Virtualization[/\s:=-]+(?P<version>\d+(?:\.\d+){1,4})",),
        priority=113, allow_body=True,
    ),
    _rule(
        "libvirt", "hypervisor", "libvirt", "libvirt", "libvirt", "libvirt",
        r"\blibvirt[/\s:=-]+(?P<version>\d+(?:\.\d+){1,4})\b",
        priority=112, allow_body=False,
        version_caveat="Distribution package revisions and backported fixes must be checked before declaring exposure.",
    ),

    # Baseboard and out-of-band management controllers.
    _rule(
        "dell-idrac10", "bmc", "Dell", "iDRAC10", "dell", "idrac10",
        r"\biDRAC\s*10\b", r"\bIntegrated\s+Dell\s+Remote\s+Access\s+Controller\s*10\b",
        version_patterns=(r"(?i)\b(?:firmware|version)\s*[:=]?\s*(?P<version>\d+(?:\.\d+){1,4})",),
        priority=123, allow_body=True,
    ),
    _rule(
        "dell-idrac9", "bmc", "Dell", "iDRAC9", "dell", "idrac9",
        r"\biDRAC\s*9\b", r"\bIntegrated\s+Dell\s+Remote\s+Access\s+Controller\s*9\b",
        version_patterns=(r"(?i)\b(?:firmware|version)\s*[:=]?\s*(?P<version>\d+(?:\.\d+){1,4})",),
        priority=122, allow_body=True,
    ),
    _rule(
        "dell-idrac8", "bmc", "Dell", "iDRAC8", "dell", "idrac8",
        r"\biDRAC\s*8\b", r"\bIntegrated\s+Dell\s+Remote\s+Access\s+Controller\s*8\b",
        version_patterns=(r"(?i)\b(?:firmware|version)\s*[:=]?\s*(?P<version>\d+(?:\.\d+){1,4})",),
        priority=121, allow_body=True,
    ),
    _rule(
        "dell-idrac", "bmc", "Dell", "Integrated Dell Remote Access Controller",
        "dell", "idrac",
        r"\bIntegrated\s+Dell\s+Remote\s+Access\s+Controller\b", r"\biDRAC\b",
        version_patterns=(r"(?i)\b(?:firmware|version)\s*[:=]?\s*(?P<version>\d+(?:\.\d+){1,4})",),
        priority=120, allow_body=True,
    ),
    _rule(
        "hpe-ilo5", "bmc", "HPE", "Integrated Lights-Out 5", "hp", "integrated lights-out 5",
        r"\b(?:HPE?|Hewlett\s+Packard\s+Enterprise)\s+iLO\s*5\b", r"\biLO\s*5\b",
        version_patterns=(r"(?i)\b(?:firmware|version)\s*[:=]?\s*(?P<version>\d+(?:\.\d+){1,4})",),
        priority=119, allow_body=True,
    ),
    _rule(
        "hpe-ilo4", "bmc", "HPE", "Integrated Lights-Out 4", "hp", "integrated lights-out 4",
        r"\b(?:HPE?|HP)\s+iLO\s*4\b", r"\biLO\s*4\b",
        version_patterns=(r"(?i)\b(?:firmware|version)\s*[:=]?\s*(?P<version>\d+(?:\.\d+){1,4})",),
        priority=118, allow_body=True,
    ),
    _rule(
        "hpe-ilo", "bmc", "HPE", "Integrated Lights-Out", "hpe", "integrated lights-out",
        r"\b(?:HP|HPE|Hewlett\s+Packard\s+Enterprise)\s+Integrated\s+Lights-Out\b",
        r"\bIntegrated\s+Lights-Out\b",
        version_patterns=(r"(?i)\b(?:firmware|version)\s*[:=]?\s*(?P<version>\d+(?:\.\d+){1,4})",),
        priority=117, allow_body=True,
    ),
    _rule(
        "lenovo-xclarity", "bmc", "Lenovo", "XClarity Controller",
        "lenovo", "xclarity_controller",
        r"\bLenovo\s+XClarity\s+Controller\b", r"\bXClarity\s+Controller\b",
        version_patterns=(r"(?i)\bXClarity\s+Controller[/\s:=-]+(?P<version>[0-9A-Za-z._+-]+)",),
        priority=116, allow_body=True,
    ),
    _rule(
        "supermicro-bmc", "bmc", "Supermicro", "BMC", "supermicro", "bmc",
        r"(?is)\bSupermicro\b.{0,100}\b(?:BMC|IPMI)\b",
        r"(?is)\b(?:BMC|IPMI)\b.{0,100}\bSupermicro\b",
        version_patterns=(r"(?i)\b(?:BMC\s+)?(?:firmware|version)\s*[:=]?\s*(?P<version>\d+(?:\.\d+){1,4})",),
        priority=115, allow_body=True,
    ),
    _rule(
        "fujitsu-irmc", "bmc", "Fujitsu", "iRMC", "fujitsu", "irmc",
        r"\bFujitsu\s+iRMC\b", r"\biRMC\s+S[4-7]\b",
        version_patterns=(r"(?i)\biRMC(?:\s+S[4-7])?[/\s:=-]+(?P<version>\d+(?:\.\d+){1,4})",),
        priority=114, allow_body=True,
    ),
    _rule(
        "oracle-ilom", "bmc", "Oracle", "Integrated Lights Out Manager",
        "oracle", "integrated lights out manager",
        r"\bOracle\s+ILOM\b", r"\bSun\s+Integrated\s+Lights\s+Out\s+Manager\b",
        r"\bOracle\s+Integrated\s+Lights\s+Out\s+Manager\b",
        version_patterns=(r"(?i)\b(?:ILOM|Manager)[/\s:=-]+(?P<version>\d+(?:\.\d+){1,4})",),
        priority=113, allow_body=True,
    ),
    _rule(
        "cisco-cimc", "bmc", "Cisco", "Integrated Management Controller",
        "cisco", "integrated_management_controller",
        r"\bCisco\s+Integrated\s+Management\s+Controller\b", r"\bCisco\s+CIMC\b",
        version_patterns=(r"(?i)\bCIMC[/\s:=-]+(?P<version>[0-9A-Za-z.()_-]+)",),
        priority=112, allow_body=True,
    ),

    # Network and security appliances with distinctive operating systems.
    _rule(
        "siemens-industrial", "network_appliance", "Siemens", "Siemens network device",
        "siemens", "scalance",
        r"\b(?P<product>(?:SCALANCE|RUGGEDCOM)\s+[A-Z]{1,5}\d{2,4}(?:[-/][A-Z0-9]+){0,4})\b",
        r"\b(?P<product>SIMATIC\s+(?:S7|ET)\s*[- ]?\d{2,4}(?:[-/][A-Z0-9]+){0,3})\b",
        version_patterns=(r"(?i)\b(?:firmware|software|version|v)\s*[:=]?\s*(?P<version>\d+(?:\.\d+){1,5})",),
        priority=111, allow_body=True,
    ),
    _rule(
        "cisco-ios", "network_appliance", "Cisco", "Cisco IOS", "cisco", "ios",
        r"\bCisco\s+IOS(?!\s+XE)\b",
        version_patterns=(r"(?i)\bCisco\s+IOS\s+Software.*?\bVersion\s+(?P<version>[0-9A-Za-z.()_-]+)",),
        priority=110, allow_body=True,
    ),
    _rule(
        "cisco-ios-xe", "network_appliance", "Cisco", "Cisco IOS XE", "cisco", "ios xe",
        r"\bCisco\s+IOS\s+XE\b",
        version_patterns=(r"(?i)\bCisco\s+IOS\s+XE\s+Software.*?\bVersion\s+(?P<version>[0-9A-Za-z.()_-]+)",),
        priority=111, allow_body=True,
    ),
    _rule(
        "cisco-nx-os", "network_appliance", "Cisco", "Cisco NX-OS", "cisco", "nx-os",
        r"\bCisco\s+NX-OS\b", r"\bNX-OS\b",
        version_patterns=(r"(?i)\bNX-OS(?:\s+Software)?[/\s:=-]+(?:version\s*)?(?P<version>[0-9A-Za-z.()_-]+)",),
        priority=109, allow_body=True,
    ),
    _rule(
        "fortinet-fortios", "network_appliance", "Fortinet", "FortiOS", "fortinet", "fortios",
        r"\bFortiOS\b", r"\bFortiGate\b",
        version_patterns=(r"(?i)\bFortiOS[/\s:=-]+v?(?P<version>\d+(?:\.\d+){1,4})",),
        priority=108, allow_body=True,
    ),
    _rule(
        "paloalto-panos", "network_appliance", "Palo Alto Networks", "PAN-OS",
        "palo alto networks", "pan-os", r"\bPAN-OS\b", r"\bPalo\s+Alto\s+Networks\b",
        version_patterns=(r"(?i)\bPAN-OS[/\s:=-]+v?(?P<version>\d+(?:\.\d+){1,4})",),
        priority=107, allow_body=True,
    ),
    _rule(
        "sonicwall-sonicos", "network_appliance", "SonicWall", "SonicOS",
        "sonicwall", "sonicos", r"\bSonicOS\b", r"\bSonicWall\b",
        version_patterns=(r"(?i)\bSonicOS[/\s:=-]+(?P<version>\d+(?:\.\d+){1,5})",),
        priority=106, allow_body=True,
    ),
    _rule(
        "mikrotik-routeros", "network_appliance", "MikroTik", "RouterOS",
        "mikrotik", "routeros", r"\bMikroTik\s+RouterOS\b", r"\bRouterOS\b",
        version_patterns=(r"(?i)\bRouterOS[/\s:=-]+v?(?P<version>\d+(?:\.\d+){1,4})",),
        priority=105, allow_body=True,
    ),
    _rule(
        "ubiquiti-edgeos", "network_appliance", "Ubiquiti", "EdgeOS", "ubiquiti", "edgeos",
        r"\bUbiquiti\s+EdgeOS\b", r"\bEdgeOS\b",
        version_patterns=(r"(?i)\bEdgeOS[/\s:=-]+v?(?P<version>\d+(?:\.\d+){1,4})",),
        priority=104, allow_body=True,
    ),
    _rule(
        "juniper-junos", "network_appliance", "Juniper Networks", "Junos OS",
        "juniper", "junos", r"\bJUNOS\b", r"\bJuniper\s+Junos\b",
        version_patterns=(r"(?i)\bJUNOS[/\s:=-]+(?P<version>[0-9A-Za-z.()_-]+)",),
        priority=103, allow_body=True,
    ),
    _rule(
        "f5-bigip", "network_appliance", "F5", "BIG-IP", "f5", "big-ip",
        r"\bF5\s+BIG-IP\b", r"\bBIG-IP\b",
        version_patterns=(r"(?i)\bBIG-IP[/\s:=-]+v?(?P<version>\d+(?:\.\d+){1,4})",),
        priority=102, allow_body=True,
    ),
    _rule(
        "citrix-adc", "network_appliance", "Citrix", "NetScaler ADC", "citrix", "netscaler adc",
        r"\bCitrix\s+(?:ADC|NetScaler)\b", r"\bNetScaler\s+ADC\b",
        version_patterns=(r"(?i)\b(?:ADC|NetScaler)[/\s:=-]+(?P<version>\d+(?:\.\d+){1,4})",),
        priority=101, allow_body=True,
    ),
    _rule(
        "netgate-pfsense", "network_appliance", "Netgate", "pfSense", "netgate", "pfsense",
        r"\bpfSense(?:\s+(?:CE|Plus))?\b",
        version_patterns=(r"(?i)\bpfSense(?:\s+(?:CE|Plus))?[/\s:=-]+(?P<version>\d+(?:\.\d+){1,4})",),
        priority=100, allow_body=True,
    ),
    _rule(
        "opnsense", "network_appliance", "OPNsense", "OPNsense", "opnsense", "opnsense",
        r"\bOPNsense\b",
        version_patterns=(r"(?i)\bOPNsense[/\s:=-]+(?P<version>\d+(?:\.\d+){1,4})",),
        priority=99, allow_body=True,
    ),
    _rule(
        "openwrt", "network_appliance", "OpenWrt", "OpenWrt", "openwrt", "openwrt",
        r"\bOpenWrt\b", version_patterns=(r"(?i)\bOpenWrt[/\s:=-]+(?P<version>\d+(?:\.\d+){1,4})",),
        priority=98, allow_body=True,
    ),
    _rule(
        "truenas", "storage_management", "iXsystems", "TrueNAS", "ixsystems", "truenas",
        r"\bTrueNAS(?:\s+(?:CORE|SCALE))?\b",
        version_patterns=(r"(?i)\bTrueNAS(?:\s+(?:CORE|SCALE))?[/\s:=-]+(?P<version>[0-9A-Za-z._+-]+)",),
        priority=97, allow_body=True,
    ),
    _rule(
        "synology-dsm", "storage_management", "Synology", "DiskStation Manager",
        "synology", "dsm", r"\bSynology\s+(?:DiskStation\s+Manager|DSM)\b", r"\bDiskStation\s+Manager\b",
        version_patterns=(r"(?i)\bDSM[/\s:=-]+(?P<version>\d+(?:\.\d+){1,4}(?:-[0-9]+)?)",),
        priority=96, allow_body=True,
    ),
    _rule(
        "qnap-qts", "storage_management", "QNAP", "QTS", "qnap", "qts",
        r"\bQNAP\s+QTS\b", r"\bQTS\s+Administration\b",
        version_patterns=(r"(?i)\bQTS[/\s:=-]+(?P<version>\d+(?:\.\d+){1,4}(?:-[0-9]+)?)",),
        priority=95, allow_body=True,
    ),
    _rule(
        "rancher", "cloud_management", "Rancher", "Rancher", "rancher", "rancher",
        r"\bRancher(?:\s+Manager)?(?:/(?P<version>\d+(?:\.\d+){1,3}))?\b",
        priority=94, allow_body=True,
    ),
    _rule(
        "portainer", "cloud_management", "Portainer", "Portainer", "portainer", "portainer",
        r"\bPortainer(?:\s+(?:CE|Business\s+Edition))?(?:/(?P<version>\d+(?:\.\d+){1,3}))?\b",
        priority=93, allow_body=True,
    ),
    _rule(
        "cockpit", "server_management", "Cockpit Project", "Cockpit",
        "cockpit-project", "cockpit", r"\bCockpit\s+(?:Web\s+Console|Server\s+Manager)\b",
        version_patterns=(r"(?i)\bCockpit[/\s:=-]+(?P<version>\d+(?:\.\d+){0,3})",),
        priority=92, allow_body=True,
        version_caveat="Use the operating-system package release when assessing Cockpit CVEs.",
    ),
    _rule(
        "windows-admin-center", "server_management", "Microsoft", "Windows Admin Center",
        "microsoft", "windows admin center", r"\bWindows\s+Admin\s+Center\b",
        version_patterns=(r"(?i)\bWindows\s+Admin\s+Center[/\s:=-]+(?P<version>\d+(?:\.\d+){0,3})",),
        priority=91, allow_body=True,
    ),
    _rule(
        "kubernetes-api", "cloud_management", "Kubernetes", "Kubernetes",
        "kubernetes", "kubernetes", r"\bKubernetes\s+API(?:\s+Server)?\b",
        version_patterns=(
            r'(?i)"gitVersion"\s*:\s*"v?(?P<version>\d+(?:\.\d+){1,3})"',
            r"(?i)\bKubernetes\s+API(?:\s+Server)?[/\s:=-]+v?(?P<version>\d+(?:\.\d+){1,3})",
        ),
        priority=90, allow_body=True,
    ),

    # Common server operating systems and network-facing applications. Banner
    # versions are useful evidence but may not reflect distribution backports.
    _rule(
        "microsoft-windows-server", "server_os", "Microsoft", "Windows Server",
        "microsoft", "windows server",
        r"\bMicrosoft\s+Windows\s+Server(?:\s+(?P<version>20\d{2}))?\b",
        r"\bWindows\s+Server\s+(?P<version>20\d{2})\b",
        priority=85, allow_body=False,
        version_caveat="Edition/build and installed security updates must be verified; a product-name match alone is not enough.",
    ),
    _rule(
        "microsoft-exchange", "server_application", "Microsoft", "Exchange Server",
        "microsoft", "exchange server",
        r"\bMicrosoft\s+Exchange(?:\s+Server)?\b", r"\bX-OWA-Version\b", r"\bX-FEServer\b",
        version_patterns=(
            r"(?i)\bX-OWA-Version\s*[:=]\s*(?P<version>\d+(?:\.\d+){2,4})",
            r"(?i)\bExchange(?:\s+Server)?[/\s:=-]+(?P<version>\d+(?:\.\d+){1,4})",
        ), priority=84, allow_body=True,
    ),
    _rule(
        "microsoft-iis", "server_application", "Microsoft", "Internet Information Services",
        "microsoft", "internet information services",
        r"\bMicrosoft-IIS(?:/(?P<version>\d+(?:\.\d+){0,3}))?\b",
        r"\bInternet\s+Information\s+Services\b",
        priority=83, allow_body=False,
        version_caveat="Windows servicing level must be checked; IIS banners do not prove patch state.",
    ),
    _rule(
        "apache-httpd", "server_application", "Apache", "HTTP Server", "apache", "http server",
        r"\bApache(?:\s+HTTP\s+Server)?/(?P<version>\d+(?:\.\d+){1,3})\b",
        r"\bApache\s+httpd(?:[/\s:=-]+(?P<version>\d+(?:\.\d+){1,3}))?\b",
        r"\bApache\s+HTTP\s+Server\b",
        priority=80, allow_body=False,
        version_caveat="Distribution packages often backport fixes without changing the visible upstream banner.",
    ),
    _rule(
        "apache-tomcat", "server_application", "Apache", "Tomcat", "apache", "tomcat",
        r"\bApache\s+Tomcat(?:/(?P<version>\d+(?:\.\d+){1,3}))?\b",
        r"\bTomcat/(?P<version>\d+(?:\.\d+){1,3})\b",
        priority=79, allow_body=True,
        version_caveat="Confirm the deployed Tomcat build rather than relying only on an error page or proxy banner.",
    ),
    _rule(
        "nginx", "server_application", "nginx", "nginx", "nginx", "nginx",
        r"\bnginx(?:/(?P<version>\d+(?:\.\d+){1,3}))?\b",
        version_patterns=(r"(?i)\bnginx[/\s:=-]+(?P<version>\d+(?:\.\d+){1,3})",),
        priority=78, allow_body=False,
        version_caveat="Distribution packages can backport security fixes without changing the upstream-looking banner.",
    ),
    _rule(
        "openssh", "server_application", "OpenBSD", "OpenSSH", "openbsd", "openssh",
        r"\bOpenSSH[_/ -]v?(?P<version>\d+(?:\.\d+){1,3}p?\d*)\b",
        priority=77, allow_body=False,
        version_caveat="The operating-system package revision and backported patches must be checked before declaring exposure.",
    ),
    _rule(
        "grafana", "server_application", "Grafana", "Grafana", "grafana", "grafana",
        r"\bX-Grafana-Version\s*[:=]\s*(?P<version>[0-9A-Za-z._+-]+)",
        r"\bGrafana(?:/(?P<version>\d+(?:\.\d+){1,3}))?\b",
        priority=76, allow_body=True,
    ),
    _rule(
        "jenkins", "server_application", "Jenkins", "Jenkins", "jenkins", "jenkins",
        r"\bX-Jenkins\s*[:=]\s*(?P<version>[0-9A-Za-z._+-]+)",
        r"\bJenkins(?:/(?P<version>\d+(?:\.\d+){1,3}))?\b",
        priority=75, allow_body=True,
    ),
    _rule(
        "gitlab", "server_application", "GitLab", "GitLab", "gitlab", "gitlab",
        r"\bGitLab(?:/(?P<version>\d+(?:\.\d+){1,3}))?\b", r"\bX-GitLab-Meta\b",
        priority=74, allow_body=True,
    ),
    _rule(
        "atlassian-confluence", "server_application", "Atlassian", "Confluence",
        "atlassian", "confluence",
        r"\bAtlassian\s+Confluence\b", r"\bConfluence(?:/(?P<version>\d+(?:\.\d+){1,3}))?\b",
        version_patterns=(r"(?i)\bajs-version-number\s*[:=]\s*(?P<version>\d+(?:\.\d+){1,3})",),
        priority=73, allow_body=True,
    ),
    _rule(
        "atlassian-jira", "server_application", "Atlassian", "Jira", "atlassian", "jira",
        r"\bAtlassian\s+Jira\b", r"\bJira(?:\s+Software)?(?:/(?P<version>\d+(?:\.\d+){1,3}))?\b",
        version_patterns=(r"(?i)\bajs-version-number\s*[:=]\s*(?P<version>\d+(?:\.\d+){1,3})",),
        priority=72, allow_body=True,
    ),
    _rule(
        "docker-engine", "server_application", "Docker", "Docker Engine",
        "docker", "docker engine", r"\bDocker\s+Engine\b", r"\bDocker/(?P<version>\d+(?:\.\d+){1,3})\b",
        priority=71, allow_body=False,
    ),
    _rule(
        "kubernetes-dashboard", "cloud_management", "Kubernetes", "Dashboard",
        "kubernetes", "dashboard", r"\bKubernetes\s+Dashboard\b",
        version_patterns=(r"(?i)\bKubernetes\s+Dashboard[/\s:=-]+v?(?P<version>\d+(?:\.\d+){1,3})",),
        priority=70, allow_body=True,
    ),
    _rule(
        "harbor", "server_application", "Harbor", "Harbor", "harbor", "harbor",
        r"\bHarbor\s+Container\s+Registry\b", r"\bHarbor/(?P<version>\d+(?:\.\d+){1,3})\b",
        priority=69, allow_body=True,
    ),
    _rule(
        "veeam-backup", "server_application", "Veeam", "Backup & Replication",
        "veeam", "backup & replication", r"\bVeeam\s+Backup\s*&\s*Replication\b",
        version_patterns=(r"(?i)\bBackup\s*&\s*Replication[/\s:=-]+(?P<version>\d+(?:\.\d+){1,4})",),
        priority=68, allow_body=True,
    ),
)


VENDOR_PATTERNS: tuple[tuple[str, str], ...] = (
    ("VMware", r"\b(?:VMware|vSphere)\b"),
    ("Proxmox", r"\b(?:Proxmox|PVEAuthCookie)\b"),
    ("Microsoft", r"\b(?:Microsoft|Windows\s+Server|Hyper-V)\b"),
    ("Nutanix", r"\bNutanix\b"),
    ("Dell", r"\b(?:Dell|iDRAC)\b"),
    ("HPE", r"\b(?:HPE|Hewlett\s+Packard\s+Enterprise|Integrated\s+Lights-Out)\b"),
    ("Lenovo", r"\b(?:Lenovo|XClarity)\b"),
    ("Supermicro", r"\bSupermicro\b"),
    ("Fujitsu", r"\b(?:Fujitsu|iRMC)\b"),
    ("Oracle", r"\b(?:Oracle\s+ILOM|Oracle\s+Integrated\s+Lights\s+Out)\b"),
    ("Siemens", r"\b(?:Siemens|SCALANCE|RUGGEDCOM|SIMATIC|SIPLUS|SINAMICS)\b"),
    ("Cisco", r"\b(?:Cisco|IOS\s+XE|NX-OS|CIMC)\b"),
    ("Fortinet", r"\b(?:Fortinet|FortiGate|FortiOS)\b"),
    ("Palo Alto Networks", r"\b(?:Palo\s+Alto\s+Networks|PAN-OS)\b"),
    ("SonicWall", r"\b(?:SonicWall|SonicOS)\b"),
    ("MikroTik", r"\b(?:MikroTik|RouterOS)\b"),
    ("Ubiquiti", r"\b(?:Ubiquiti|EdgeOS|UniFi)\b"),
    ("ZTE", r"\b(?:ZTE|ztedevice)\b"),
)


def _clean(value: object, limit: int = 240) -> str:
    text = _CONTROL_CHARS.sub(" ", str(value or ""))
    return re.sub(r"\s+", " ", text).strip()[:limit]


def identify_vendor(text: str) -> str:
    bounded = str(text or "")[:524288]
    return next(
        (vendor for vendor, pattern in VENDOR_PATTERNS if re.search(pattern, bounded, re.IGNORECASE)),
        "",
    )


def _captured(match: re.Match[str], name: str) -> str:
    try:
        return str(match.groupdict().get(name) or "")
    except (IndexError, AttributeError):
        return ""


def _version_for(rule: ProductFingerprintRule, text: str, match: re.Match[str]) -> str:
    raw = _captured(match, "version")
    if not raw:
        for pattern in rule.version_patterns:
            version_match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
            if version_match:
                raw = _captured(version_match, "version")
                if raw:
                    break
    cleaned = _clean(raw, 80).lstrip("vV")
    return cleaned if _SAFE_VERSION.fullmatch(cleaned) else ""


def identify_product_fingerprints(
    text: str,
    *,
    source: str,
    body_context: bool = False,
    limit: int = 16,
) -> list[dict[str, object]]:
    """Return bounded structured identities from concrete product signatures.

    ``body_context`` restricts matching to products with distinctive branded
    management-page markers. Generic server words such as ``nginx`` are only
    accepted from metadata/banners, avoiding CVE searches caused by prose in a
    page body.
    """
    bounded = str(text or "")[:524288]
    if not bounded:
        return []
    results: list[dict[str, object]] = []
    seen: set[tuple[str, str, str]] = set()
    for rule in sorted(PRODUCT_FINGERPRINT_RULES, key=lambda item: -item.priority):
        if body_context and not rule.allow_body:
            continue
        signature_match: re.Match[str] | None = None
        for pattern in rule.patterns:
            signature_match = re.search(pattern, bounded, re.IGNORECASE | re.DOTALL)
            if signature_match:
                break
        if not signature_match:
            continue
        if rule.key == "dell-idrac" and any(
            str(item.get("fingerprint_id") or "").startswith("dell-idrac")
            for item in results
        ):
            continue
        product = _clean(_captured(signature_match, "product") or rule.product, 200)
        version = _version_for(rule, bounded, signature_match)
        key = (rule.vendor.lower(), product.lower(), version.lower())
        if key in seen:
            continue
        seen.add(key)
        evidence = _clean(signature_match.group(0), 200)
        results.append({
            "fingerprint_id": rule.key,
            "category": rule.category,
            "vendor": rule.vendor,
            "product": product,
            "version": version,
            "evidence": evidence,
            "source": _clean(source, 80),
            "confidence": rule.confidence,
            "priority": rule.priority,
            "search_vendor": rule.search_vendor,
            "search_product": (
                product if rule.key == "siemens-industrial" else rule.search_product
            ),
            "cve_searchable": rule.cve_searchable,
            "version_caveat": rule.version_caveat,
        })
        if len(results) >= max(1, min(int(limit), 40)):
            break
    return results
