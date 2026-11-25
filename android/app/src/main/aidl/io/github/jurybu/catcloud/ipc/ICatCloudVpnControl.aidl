package io.github.jurybu.catcloud.ipc;

interface ICatCloudVpnControl {
    String getStatusJson();
    String startVpn(
        String configPath,
        String perAppMode,
        in String[] perAppPackages,
        String activeNodeName,
        String controllerGroupName,
        int activeNodeCount
    );
    String reloadVpn(
        String configPath,
        String activeNodeName,
        String controllerGroupName,
        int activeNodeCount
    );
    void stopVpn();
    String forceRestartCore();
    void forceGc();
    void setWatchdogPaused(boolean paused);
}
