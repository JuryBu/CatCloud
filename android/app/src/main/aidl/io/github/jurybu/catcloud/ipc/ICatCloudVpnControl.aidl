package io.github.jurybu.catcloud.ipc;

interface ICatCloudVpnControl {
    String getStatusJson();
    String startVpn(
        String configPath,
        String perAppMode,
        in String[] perAppPackages,
        String activeNodeName,
        int activeNodeCount
    );
    String reloadVpn(
        String configPath,
        String activeNodeName,
        int activeNodeCount
    );
    void stopVpn();
    String forceRestartCore();
    void forceGc();
}
