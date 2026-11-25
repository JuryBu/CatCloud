#ifndef CATCLOUD_JNI_H
#define CATCLOUD_JNI_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Socket protection callback implemented in catcloud_jni.c and invoked from
 * Go's permanent dialer.DefaultSocketHook on arbitrary Go OS threads.
 * Returns non-zero (1) when Android VpnService.protect(fd) succeeds, 0 otherwise.
 */
int catcloud_protect_socket(int fd);

#ifdef CATCLOUD_JNI_IMPL
/*
 * Go-exported C entry points (implemented in bridge.go via //export).
 * Parameter types strictly match cgo's generated _cgo_export.h ABI:
 *   *C.char    -> char*
 *   C.int      -> int
 *   C.longlong -> long long
 * Any non-NULL char* return value is heap-allocated by Go C.CString and MUST
 * be released by the C caller with free(). NULL indicates success.
 */
extern char* catcloud_go_init(char* homeDir);
extern void catcloud_go_set_memory_limit(long long limitBytes, int gcPercent);
extern char* catcloud_go_prepare_config(char* configYaml, char* controllerAddr, char* controllerSecret);
extern char* catcloud_go_attach_tun(int tunFd, int mtu);
extern char* catcloud_go_reload_config(char* configYaml);
extern void catcloud_go_stop_tun(void);
extern void catcloud_go_update_system_dns(char* dnsCsv);
extern void catcloud_go_reset_network(void);
extern void catcloud_go_force_gc(void);
#endif

#ifdef __cplusplus
}
#endif

#endif /* CATCLOUD_JNI_H */
