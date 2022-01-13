// --- BEGIN COPYRIGHT BLOCK ---
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation;
// version 2.1 of the License.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor,
// Boston, MA  02110-1301  USA 
// 
// Copyright (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

#ifdef __cplusplus
extern "C"
{
#endif
#include <stdio.h>
//#include <wchar.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "httpd/httpd.h"
#include "prmem.h"
#include "prsystem.h"
#include "plstr.h"
#include "prio.h"
#include "prprf.h"
#include "plhash.h"
#include "pk11func.h"
#include "cert.h"
#include "certt.h"
#include "secerr.h"
#include "tus/tus_db.h"
#include "secder.h"
#include "nss.h"
#include "nssb64.h"

#ifdef __cplusplus
}
#endif

#include "main/Memory.h"
#include "main/ConfigStore.h"
#include "main/RA_Context.h"
#include "channel/Secure_Channel.h"
#include "engine/RA.h"
#include "main/Util.h"
#include "cms/HttpConnection.h"
#include "main/RA_pblock.h"
#include "main/LogFile.h"

typedef struct
{
    enum
    {
        PW_NONE = 0,
        PW_FROMFILE = 1,
        PW_PLAINTEXT = 2,
        PW_EXTERNAL = 3
    } source;
    char *data;
} secuPWData;


static ConfigStore *m_cfg = NULL;
static LogFile* m_debug_log = (LogFile *)NULL; 
static LogFile* m_error_log = (LogFile *)NULL; 
static LogFile* m_audit_log = (LogFile *)NULL; 

RA_Context *RA::m_ctx = NULL;
bool RA::m_pod_enable=false;
int RA::m_pod_curr = 0;
PRLock *RA::m_pod_lock = NULL;
PRLock *RA::m_verify_lock = NULL;
PRLock *RA::m_debug_log_lock = NULL;
PRLock *RA::m_error_log_lock = NULL;
PRLock *RA::m_config_lock = NULL;
PRMonitor *RA::m_audit_log_monitor = NULL;
bool RA::m_audit_enabled = false;
bool RA::m_audit_signed = false;
SECKEYPrivateKey *RA::m_audit_signing_key = NULL;
NSSUTF8 *RA::m_last_audit_signature = NULL;
SECOidTag RA::m_audit_signAlgTag;
SecurityLevel RA::m_global_security_level;
char *RA::m_signedAuditSelectedEvents = NULL;
char *RA::m_signedAuditSelectableEvents = NULL;
char *RA::m_signedAuditNonSelectableEvents = NULL;

char *RA::m_audit_log_buffer = NULL;
PRThread *RA::m_flush_thread = (PRThread *) NULL;
size_t RA::m_bytes_unflushed =0;
size_t RA::m_buffer_size = 512;
int RA::m_flush_interval = 5;

int RA::m_audit_log_level = (int) LL_PER_SERVER;
int RA::m_debug_log_level = (int) LL_PER_SERVER;
int RA::m_error_log_level = (int) LL_PER_SERVER;
int RA::m_caConns_len = 0;
int RA::m_tksConns_len = 0;
int RA::m_drmConns_len = 0;

#define MAX_BODY_LEN 4096

#define MAX_CA_CONNECTIONS 20
#define MAX_TKS_CONNECTIONS 20
#define MAX_DRM_CONNECTIONS 20
#define MAX_AUTH_LIST_MEMBERS 20
HttpConnection* RA::m_caConnection[MAX_CA_CONNECTIONS];
HttpConnection* RA::m_tksConnection[MAX_TKS_CONNECTIONS];
HttpConnection* RA::m_drmConnection[MAX_DRM_CONNECTIONS];

/* TKS response parameters */
const char *RA::TKS_RESPONSE_STATUS = "status";
const char *RA::TKS_RESPONSE_SessionKey = "sessionKey";
const char *RA::TKS_RESPONSE_EncSessionKey = "encSessionKey";
const char *RA::TKS_RESPONSE_KEK_DesKey = "kek_wrapped_desKey";
const char *RA::TKS_RESPONSE_DRM_Trans_DesKey = "drm_trans_wrapped_desKey";
const char *RA::TKS_RESPONSE_HostCryptogram = "hostCryptogram";

const char *RA::CFG_DEBUG_ENABLE = "logging.debug.enable"; 
const char *RA::CFG_DEBUG_FILENAME = "logging.debug.filename"; 
const char *RA::CFG_DEBUG_LEVEL = "logging.debug.level";
const char *RA::CFG_AUDIT_ENABLE = "logging.audit.enable"; 
const char *RA::CFG_AUDIT_FILENAME = "logging.audit.filename"; 
const char *RA::CFG_SIGNED_AUDIT_FILENAME = "logging.audit.signedAuditFilename"; 
const char *RA::CFG_AUDIT_LEVEL = "logging.audit.level";
const char *RA::CFG_AUDIT_SIGNED = "logging.audit.logSigning";
const char *RA::CFG_AUDIT_SIGNING_CERT_NICK = "logging.audit.signedAuditCertNickname";
const char *RA::CFG_ERROR_ENABLE = "logging.error.enable"; 
const char *RA::CFG_ERROR_FILENAME = "logging.error.filename"; 
const char *RA::CFG_ERROR_LEVEL = "logging.error.level";
const char *RA::CFG_SELFTEST_ENABLE = "selftests.container.logger.enable";
const char *RA::CFG_SELFTEST_FILENAME = "selftests.container.logger.fileName";
const char *RA::CFG_SELFTEST_LEVEL = "selftests.container.logger.level";
const char *RA::CFG_CHANNEL_SEC_LEVEL = "channel.securityLevel"; 
const char *RA::CFG_CHANNEL_ENCRYPTION = "channel.encryption";
const char *RA::CFG_APPLET_CARDMGR_INSTANCE_AID = "applet.aid.cardmgr_instance"; 
const char *RA::CFG_APPLET_NETKEY_INSTANCE_AID = "applet.aid.netkey_instance"; 
const char *RA::CFG_APPLET_NETKEY_FILE_AID = "applet.aid.netkey_file"; 
const char *RA::CFG_APPLET_NETKEY_OLD_INSTANCE_AID = "applet.aid.netkey_old_instance"; 
const char *RA::CFG_APPLET_NETKEY_OLD_FILE_AID = "applet.aid.netkey_old_file"; 
const char *RA::CFG_APPLET_SO_PIN = "applet.so_pin"; 
const char *RA::CFG_APPLET_DELETE_NETKEY_OLD = "applet.delete_old"; 
const char *RA::CFG_AUDIT_SELECTED_EVENTS="logging.audit.selected.events";
const char *RA::CFG_AUDIT_NONSELECTABLE_EVENTS="logging.audit.nonselectable.events";
const char *RA::CFG_AUDIT_SELECTABLE_EVENTS="logging.audit.selectable.events";
const char *RA::CFG_AUDIT_BUFFER_SIZE = "logging.audit.buffer.size";
const char *RA::CFG_AUDIT_FLUSH_INTERVAL = "logging.audit.flush.interval";
const char *RA::CFG_AUDIT_FILE_TYPE = "logging.audit.file.type";
const char *RA::CFG_DEBUG_FILE_TYPE = "logging.debug.file.type";
const char *RA::CFG_ERROR_FILE_TYPE = "logging.error.file.type";
const char *RA::CFG_SELFTEST_FILE_TYPE = "selftests.container.logger.file.type";
const char *RA::CFG_AUDIT_PREFIX = "logging.audit";
const char *RA::CFG_ERROR_PREFIX = "logging.error";
const char *RA::CFG_DEBUG_PREFIX = "logging.debug";
const char *RA::CFG_SELFTEST_PREFIX = "selftests.container.logger";
const char *RA::CFG_TOKENDB_ALLOWED_TRANSITIONS = "tokendb.allowedTransitions";
const char *RA::CFG_OPERATIONS_ALLOWED_TRANSITIONS = "tps.operations.allowedTransitions";

const char *RA::CFG_AUTHS_ENABLE="auth.enable";

/* default values */
const char *RA::CFG_DEF_CARDMGR_INSTANCE_AID = "A0000000030000"; 
const char *RA::CFG_DEF_NETKEY_INSTANCE_AID = "627601FF000000"; 
const char *RA::CFG_DEF_NETKEY_FILE_AID = "627601FF0000"; 
const char *RA::CFG_DEF_NETKEY_OLD_INSTANCE_AID = "A00000000101"; 
const char *RA::CFG_DEF_NETKEY_OLD_FILE_AID = "A000000001"; 
const char *RA::CFG_DEF_APPLET_SO_PIN = "000000000000"; 

extern void BuildHostPortLists(char *host, char *port, char **hostList, 
  char **portList, int len);

static char *transitionList                  = NULL;

#define MAX_TOKEN_UI_STATE  6

enum token_ui_states  {
    TOKEN_UNINITIALIZED = 0,
    TOKEN_DAMAGED =1,
    TOKEN_PERM_LOST=2,
    TOKEN_TEMP_LOST=3,
    TOKEN_FOUND =4,
    TOKEN_TEMP_LOST_PERM_LOST =5,
    TOKEN_TERMINATED = 6
};

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

/**
 * Constructs a Registration Authority object.
 */
RA::RA ()
{ 
}

/**
 * Destructs a Registration Authority object.
 */
RA::~RA ()
{
    do_free(m_signedAuditSelectedEvents);
    do_free(m_signedAuditSelectableEvents);
    do_free(m_signedAuditNonSelectableEvents);

    if (m_cfg != NULL) {
        delete m_cfg;
        m_cfg = NULL;
    }
}

TPS_PUBLIC ConfigStore *RA::GetConfigStore()
{
	return m_cfg;
}

PRLock *RA::GetVerifyLock()
{
  return m_verify_lock;
}

PRLock *RA::GetConfigLock()
{
  return m_config_lock;
}

void RA::do_free(char *p)
{
    if (p != NULL) {
        PR_Free(p);
        p = NULL;
    }
}

int RA::testTokendb() {
    // try to see if we can talk to the database
    int st = 0;
    LDAPMessage  *ldapResult = NULL;
    const char * filter = "(cn=0000000000080000*)";

    if ((st = find_tus_db_entries(filter, 0, &ldapResult)) != LDAP_SUCCESS) {
        RA::Debug("RA::testing", "response from token DB failed");
    } else {
        RA::Debug("RA::testing", "response from token DB succeeded");
    }
    if (ldapResult != NULL) {
        ldap_msgfree(ldapResult);
    }

    return st;
}

/*
 * returns true if item is a value in the comma separated list
 * used by audit logging functions and profile selection functions
 */
TPS_PUBLIC bool RA::match_comma_list(const char* item, char *list)
{
    char *pList = PL_strdup(list);
    char *sresult = NULL;
    char *lasts = NULL;

    sresult = PL_strtok_r(pList, ",", &lasts);
    while (sresult != NULL) {
        if (PL_strcmp(sresult, item) == 0) {
            if (pList != NULL) {
                PR_Free(pList);
                pList = NULL;
            }
            return true;
        }
        sresult = PL_strtok_r(NULL, ",", &lasts);
    }
    if (pList != NULL) {
        PR_Free(pList);
        pList = NULL;
    }
    return false;
}

/*
 * return comma separated list with all instances of item removed
 * must be freed by caller
 */
TPS_PUBLIC char* RA::remove_from_comma_list(const char*item, char *list)
{
    int len = PL_strlen(list);
    char *pList=PL_strdup(list);
    char *ret = (char *) PR_Malloc(len);
    char  *sresult = NULL;
    char *lasts = NULL;
    

    PR_snprintf(ret, len, "");
    sresult = PL_strtok_r(pList, ",", &lasts);
    while (sresult != NULL) {
        if (PL_strcmp(sresult, item) != 0) {
            PR_snprintf(ret, len, "%s%s%s", ret, (PL_strlen(ret)>0)? "," : "", sresult);
        }
        sresult = PL_strtok_r(NULL, ",",&lasts);
    }
    if (pList != NULL) {
        PR_Free(pList);
        pList = NULL;
    }
    return ret;
}


/*
 * returns true if an audit event is valid, false if not
 */
bool RA::IsValidEvent(const char *auditEvent)
{
    return match_comma_list(auditEvent, m_signedAuditNonSelectableEvents) ||
           match_comma_list(auditEvent, m_signedAuditSelectableEvents);
}

/*
 * returns true if an audit event is selected, false if not
 */
bool RA::IsAuditEventSelected(const char* auditEvent)
{
  return match_comma_list(auditEvent, m_signedAuditNonSelectableEvents) || 
         match_comma_list(auditEvent, m_signedAuditSelectedEvents);
}

HttpConnection *RA::GetTKSConn(const char *id) {
    HttpConnection *tksconn = NULL;
    for (int i=0; i<m_tksConns_len; i++) {
        if (strcmp(m_tksConnection[i]->GetId(), id) == 0) {
            tksconn = m_tksConnection[i];   
            break;
        }
    }
    return tksconn; 
}

HttpConnection *RA::GetDRMConn(const char *id) {
    HttpConnection *drmconn = NULL;
    for (int i=0; i<m_drmConns_len; i++) {
        if (strcmp(m_drmConnection[i]->GetId(), id) == 0) {
            drmconn = m_drmConnection[i];   
            break;
        }
    }
    return drmconn; 
}

void RA::ReturnTKSConn(HttpConnection *conn) {
    // do nothing for now
}

void RA::ReturnDRMConn(HttpConnection *conn) {
    // do nothing for now
}

HttpConnection *RA::GetCAConn(const char *id) {
    HttpConnection *caconn = NULL;
    if (id == NULL)
      return NULL;
    for (int i=0; i<m_caConns_len; i++) {
        if (strcmp(m_caConnection[i]->GetId(), id) == 0) {
            caconn = m_caConnection[i];
            break;
        }
    }
    return caconn;
}

void RA::ReturnCAConn(HttpConnection *conn) {
    // do nothing for now
}

int RA::GetPodIndex() {
    PR_Lock(m_pod_lock);
    int index = m_pod_curr;
    PR_Unlock(m_pod_lock);
    return index;
}

void RA::SetPodIndex(int index) {
    PR_Lock(m_pod_lock);
    m_pod_curr = index;
    PR_Unlock(m_pod_lock);
}

void RA::SetCurrentIndex(HttpConnection *&conn, int index) {
    PRLock *lock = conn->GetLock();
    PR_Lock(lock);
    conn->SetCurrentIndex(index);
    PR_Unlock(lock);
}

int RA::GetCurrentIndex(HttpConnection *conn) {
    PRLock *lock = conn->GetLock();
    PR_Lock(lock);
    int index = conn->GetCurrentIndex();
    PR_Unlock(lock);
    return index;
}

void RA::SetGlobalSecurityLevel(SecurityLevel sl) {
    m_global_security_level = sl;
    RA::Debug(" RA::SetGlobalSecurityLevel", "global security level set to %d", (int) sl);

}

SecurityLevel RA::GetGlobalSecurityLevel() {
    return m_global_security_level;
}


/*
 * recovers user encryption key that was previously archived.
 * It expects DRM to search its archival db by cert.
 *
 * input:
 * @param cuid (cuid of the recovering key's token)
 * @param userid (uid of the recovering key owner
 * @param desKey_s (came from TKS - session key wrapped with DRM transport
 * @param cert (base64 encoded cert of the recovering key)
 * @param connId (drm connectoin id)
 *
 * output:
 * @param publickey_s public key provided by DRM
 * @param wrappedPrivateKey_s encrypted private key provided by DRM
 * @param ivParam_s returned intialization vector
 */
void RA::RecoverKey(RA_Session *session, const char* cuid,
                    const char *userid, char* desKey_s,
                    char *b64cert, char **publicKey_s,
                    char **wrappedPrivateKey_s, const char *connId,  char **ivParam_s)
{
    int status;
    PSHttpResponse *response = NULL;
    HttpConnection *drmConn = NULL;
    char body[MAX_BODY_LEN];
    char configname[256];
    char * cert_s;
    int drm_curr = 0;
    long s;
    char * content = NULL;
    char ** hostport= NULL;
    const char* servletID = NULL;
    char *wrappedDESKey_s= NULL;
    Buffer *decodeKey = NULL;
    ConnectionInfo *connInfo = NULL;
    RA_pblock *ra_pb = NULL;
    int currRetries = 0;
    char *p = NULL;

    RA::Debug(" RA:: RecoverKey", "in RecoverKey");
    if (cuid == NULL) {
      RA::Debug(" RA:: RecoverKey", "in RecoverKey, cuid NULL");
      goto loser;
    }
    if (userid == NULL) {
      RA::Debug(" RA:: RecoverKey", "in RecoverKey, userid NULL");
      goto loser;
    }
    if (b64cert == NULL) {
      RA::Debug(" RA:: RecoverKey", "in RecoverKey, b64cert NULL");
      goto loser;
    }
    if (desKey_s == NULL) {
      RA::Debug(" RA:: RecoverKey", "in RecoverKey, desKey_s NULL");
      goto loser;
    }
    if (connId == NULL) {
      RA::Debug(" RA:: RecoverKey", "in RecoverKey, connId NULL");
      goto loser;
    }
    RA::Debug(" RA:: RecoverKey", "in RecoverKey, desKey_s=%s, connId=%s",desKey_s,  connId);

    cert_s = Util::URLEncode(b64cert);
    drmConn = RA::GetDRMConn(connId);
    if (drmConn == NULL) {
        RA::Debug(" RA:: RecoverKey", "in RecoverKey, failed getting drmconn");
	goto loser;
    }
    RA::Debug(" RA:: RecoverKey", "in RecoverKey, got drmconn");
    connInfo = drmConn->GetFailoverList();
    RA::Debug(" RA:: RecoverKey", "in RecoverKey, got drm failover");
    decodeKey = Util::URLDecode(desKey_s);
    RA::Debug(" RA:: RecoverKey", "in RecoverKey,url decoded des");
    wrappedDESKey_s = Util::SpecialURLEncode(*decodeKey);

    RA::Debug(" RA:: RecoverKey", "in RecoverKey, wrappedDESKey_s=%s", wrappedDESKey_s);

    PR_snprintf((char *)body, MAX_BODY_LEN, 
		"CUID=%s&userid=%s&drm_trans_desKey=%s&cert=%s",cuid, userid, wrappedDESKey_s, cert_s);
    RA::Debug(" RA:: RecoverKey", "in RecoverKey, body=%s", body);
        PR_snprintf((char *)configname, 256, "conn.%s.servlet.TokenKeyRecovery", connId);
        servletID = GetConfigStore()->GetConfigAsString(configname);
    RA::Debug(" RA:: RecoverKey", "in RecoverKey, configname=%s", configname);

    drm_curr = RA::GetCurrentIndex(drmConn);
    response = drmConn->getResponse(drm_curr, servletID, body);
    hostport = connInfo->GetHostPortList();
    if (response == NULL) {
        RA::Debug(LL_PER_PDU, "The recoverKey response from DRM ", 
          "at %s is NULL.", hostport[drm_curr]);
 
      //goto loser;
    } else {
        RA::Debug(LL_PER_PDU, "The recoverKey response from DRM ", 
          "at %s is not NULL.", hostport[drm_curr]);
    }

    while (response == NULL) {
        RA::Failover(drmConn, connInfo->GetHostPortListLen());
    
        drm_curr = RA::GetCurrentIndex(drmConn);
        RA::Debug(LL_PER_PDU, "RA is reconnecting to DRM ", 
          "at %s for recoverKey.", hostport[drm_curr]);
    
        if (++currRetries >= drmConn->GetNumOfRetries()) {
            RA::Debug("Used up all the retries in recoverKey. Response is NULL","");
            RA::Error("RA::RecoverKey","Failed connecting to DRM after %d retries", currRetries);

            goto loser;
        }
        response = drmConn->getResponse(drm_curr, servletID, body);
    }

    RA::Debug(" RA:: RecoverKey", "in RecoverKey - got response");
    // XXXskip handling fallback host for prototype

    content = response->getContent();
    p = strstr(content, "status=");
    content = p; //skip the HTTP header

    s = response->getStatus();

    if ((content != NULL) && (s == 200)) {
      RA::Debug("RA::RecoverKey", "response from DRM status ok");

      Buffer* status_b;
      char* status_s;

      ra_pb = ( RA_pblock * ) session->create_pblock(content);
      if (ra_pb == NULL)
	goto loser;

      status_b = ra_pb->find_val("status");
      if (status_b == NULL) {
	status = 4;
	goto loser;
      }
      else {
	status_s = status_b->string();
	status = atoi(status_s);
        if (status_s != NULL) {
            PR_Free(status_s);
        }
      }


      char * tmp = NULL;
      tmp = ra_pb->find_val_s("public_key");
      if ((tmp == NULL) || (strcmp(tmp,"")==0)) {
	RA::Error(LL_PER_PDU, "RecoverKey"," got no public key");
	goto loser;
      } else {
	RA::Debug(LL_PER_PDU, "RecoverKey", "got public key =%s", tmp);
          char *tmp_publicKey_s  = PL_strdup(tmp);
          Buffer *decodePubKey = Util::URLDecode(tmp_publicKey_s);
          *publicKey_s =
              BTOA_DataToAscii(decodePubKey->getBuf(), decodePubKey->getLen());
          if (tmp_publicKey_s)
              PR_Free (tmp_publicKey_s);
          if (decodePubKey)
              PR_Free(decodePubKey);
      }

      tmp = NULL;
      tmp = ra_pb->find_val_s("wrapped_priv_key");
      if ((tmp == NULL) || (strcmp(tmp,"")==0)) {
	RA::Error(LL_PER_PDU, "RecoverKey"," got no wrapped private key");
	//XXX	      goto loser;
      } else {
	RA::Debug(LL_PER_PDU, "RecoverKey", "got wrappedprivate key =%s", tmp);
	*wrappedPrivateKey_s  = PL_strdup(tmp);
      }

      tmp = ra_pb->find_val_s("iv_param");
      if ((tmp == NULL) || (strcmp(tmp,"")==0)) {
          RA::Error(LL_PER_PDU, "RecoverKey",
              "did not get iv_param for recovered  key in DRM response");
      } else {
          RA::Debug(LL_PER_PDU, "RecoverKey", "got iv_param for recovered key =%s", tmp);
          *ivParam_s  = PL_strdup(tmp);
      }

    } else {// if content is NULL or status not 200
      if (content != NULL)
	RA::Debug("RA::RecoverKey", "response from DRM error status %ld", s);
      else
	RA::Debug("RA::RecoverKey", "response from DRM no content");
    }
 loser:
    if (desKey_s != NULL)
      PR_Free(desKey_s);

    if (decodeKey != NULL)
      PR_Free(decodeKey);

    if (wrappedDESKey_s != NULL)
      PR_Free(wrappedDESKey_s);

    if (drmConn != NULL)
      RA::ReturnDRMConn(drmConn);

    if (response != NULL) {
      if (content != NULL)
	response->freeContent();
      delete response;
    }

    if (ra_pb != NULL) {
      delete ra_pb;
    }

}



/*
 * input:
 * @param desKey_s provided for drm to wrap user private
 * @param publicKey_s returned for key injection back to token
 *
 * Output:
 * @param publicKey_s public key provided by DRM
 * @param wrappedPrivateKey_s encrypted private key provided by DRM
 */
void RA::ServerSideKeyGen(RA_Session *session, const char* cuid,
                          const char *userid, char* desKey_s,
	                      char **publicKey_s,
                          char **wrappedPrivateKey_s,
                          char **ivParam_s, const char *connId,
                          bool archive, int keysize, bool isECC)
{

	const char *FN="RA::ServerSideKeyGen";
    int status;
    PSHttpResponse *response = NULL;
    HttpConnection *drmConn = NULL;
    char body[MAX_BODY_LEN];
    char configname[256];

    long s;
    char * content = NULL;
    char ** hostport = NULL;
    const char* servletID = NULL;
    char *wrappedDESKey_s = NULL;
    Buffer *decodeKey = NULL;
    ConnectionInfo *connInfo = NULL;
    RA_pblock *ra_pb = NULL;
    int drm_curr = 0;
    int currRetries = 0;
    char *p = NULL;

    if ((cuid == NULL) || (strcmp(cuid,"")==0)) {
      RA::Debug( LL_PER_CONNECTION, FN,
			"error: passed invalid cuid");
      goto loser;
    }
    if ((userid == NULL) || (strcmp(userid,"")==0)) {
      RA::Debug(LL_PER_CONNECTION, FN,
			"error: passed invalid userid");
      goto loser;
    }
    if ((desKey_s == NULL) || (strcmp(desKey_s,"")==0)) {
      RA::Debug(LL_PER_CONNECTION, FN, 
			 "error: passed invalid desKey_s");
      goto loser;
    }
    if ((connId == NULL) ||(strcmp(connId,"")==0)) {
      RA::Debug(LL_PER_CONNECTION, FN,
			 "error: passed invalid connId");
      goto loser;
    }
    RA::Debug(LL_PER_CONNECTION, FN,
			 "desKey_s=%s, connId=%s",desKey_s,  connId);
    drmConn = RA::GetDRMConn(connId);

    if (drmConn == NULL) {
        RA::Debug(LL_PER_CONNECTION, FN,
			"drmconn is null");
		goto loser;
    }
    RA::Debug(LL_PER_CONNECTION, FN,
			"found DRM connection info");
    connInfo = drmConn->GetFailoverList();
    RA::Debug(LL_PER_CONNECTION, FN,
		 "got DRM failover list");

    decodeKey = Util::URLDecode(desKey_s);
    if (decodeKey == NULL) {
      RA::Debug(LL_PER_CONNECTION, FN,
		"url-decoding of des key-transport-key failed");
      goto loser;
    }
    RA::Debug(LL_PER_CONNECTION, FN,
		"successfully url-decoded key-transport-key");
    wrappedDESKey_s = Util::SpecialURLEncode(*decodeKey);

    RA::Debug(LL_PER_CONNECTION, FN,
		"wrappedDESKey_s=%s", wrappedDESKey_s);

    if (isECC) {
        char *eckeycurve = NULL;
        if (keysize == 521) {
            eckeycurve = "nistp521";
        } else if (keysize == 384) {
            eckeycurve = "nistp384";
        } else if (keysize == 256) {
            eckeycurve = "nistp256";
        } else {
            RA::Debug(LL_PER_CONNECTION, FN,
                "unrecognized ECC keysize %d, setting to nistp256", keysize);
            keysize = 256;
            eckeycurve = "nistp256";
        }
        PR_snprintf((char *)body, MAX_BODY_LEN, 
           "archive=%s&CUID=%s&userid=%s&keytype=EC&eckeycurve=%s&drm_trans_desKey=%s",archive?"true":"false",cuid, userid, eckeycurve, wrappedDESKey_s);
    } else {
        PR_snprintf((char *)body, MAX_BODY_LEN, 
           "archive=%s&CUID=%s&userid=%s&keysize=%d&keytype=RSA&drm_trans_desKey=%s",archive?"true":"false",cuid, userid, keysize, wrappedDESKey_s);
    }

    RA::Debug(LL_PER_CONNECTION, FN, 
		"sending to DRM: query=%s", body);

    PR_snprintf((char *)configname, 256, "conn.%s.servlet.GenerateKeyPair", connId);
    servletID = GetConfigStore()->GetConfigAsString(configname);
    RA::Debug(LL_PER_CONNECTION, FN,
		 "finding DRM servlet info, configname=%s", configname);

    drm_curr = RA::GetCurrentIndex(drmConn);
    response = drmConn->getResponse(drm_curr, servletID, body);
    hostport = connInfo->GetHostPortList();
    if (response == NULL) {
        RA::Error(LL_PER_CONNECTION, FN, 
			"failed to get response from DRM at %s", 
			hostport[drm_curr]);
        RA::Debug(LL_PER_CONNECTION, FN, 
			"failed to get response from DRM at %s", 
			hostport[drm_curr]);
    } else { 
        RA::Debug(LL_PER_CONNECTION, FN,
			"response from DRM (%s) is not NULL.",
			 hostport[drm_curr]);
    }

    while (response == NULL) {
        RA::Failover(drmConn, connInfo->GetHostPortListLen());

        drm_curr = RA::GetCurrentIndex(drmConn);
        RA::Debug(LL_PER_CONNECTION, FN,
			"RA is failing over to DRM at %s", hostport[drm_curr]);

        if (++currRetries >= drmConn->GetNumOfRetries()) {
            RA::Debug(LL_PER_CONNECTION, FN,
				"Failed to get response from all DRMs in conn group '%s'"
				" after %d retries", connId, currRetries);
            RA::Error(LL_PER_CONNECTION, FN,
				"Failed to get response from all DRMs in conn group '%s'"
				" after %d retries", connId, currRetries);


            goto loser;
        }
        response = drmConn->getResponse(drm_curr, servletID, body);
    }

    RA::Debug(" RA:: ServerSideKeyGen", "in ServerSideKeyGen - got response");
    // XXX skip handling fallback host for prototype

    content = response->getContent();
    p = strstr(content, "status=");
    content = p; //skip the HTTP header
    s = response->getStatus();

    if ((content != NULL) && (s == 200)) {
	  RA::Debug("RA::ServerSideKeyGen", "response from DRM status ok");

	  Buffer* status_b;
	  char* status_s;

	  ra_pb = ( RA_pblock * ) session->create_pblock(content);
	  if (ra_pb == NULL)
	    goto loser;

	  status_b = ra_pb->find_val("status");
	  if (status_b == NULL) {
	    status = 4;
	    goto loser;
	  } else {
	    status_s = status_b->string();
	    status = atoi(status_s);
            if (status_s != NULL) {
                PR_Free(status_s);
            }
	  }

	  char * tmp = NULL;
	  tmp = ra_pb->find_val_s("public_key");
	  if (tmp == NULL) {
	    RA::Error(LL_PER_CONNECTION, FN,
			"Did not get public key in DRM response");
	  } else {
	    RA::Debug(LL_PER_PDU, "ServerSideKeyGen", "got public key =%s", tmp);
	    *publicKey_s  = PL_strdup(tmp);
	  }

	  tmp = NULL;
	  tmp = ra_pb->find_val_s("wrapped_priv_key");
	  if ((tmp == NULL) || (strcmp(tmp,"")==0)) {
	    RA::Error(LL_PER_CONNECTION, FN,
				"did not get wrapped private key in DRM response");
	  } else {
	    RA::Debug(LL_PER_CONNECTION, FN,
			"got wrappedprivate key =%s", tmp);
	    *wrappedPrivateKey_s  = PL_strdup(tmp);
	  }

	  tmp = ra_pb->find_val_s("iv_param");
	  if ((tmp == NULL) || (strcmp(tmp,"")==0)) {
	    RA::Error(LL_PER_CONNECTION, FN,
				"did not get iv_param for private key in DRM response");
	  } else {
	    RA::Debug(LL_PER_PDU, "ServerSideKeyGen", "got iv_param for private key =%s", tmp);
	    *ivParam_s  = PL_strdup(tmp);
	  }

    } else {// if content is NULL or status not 200
	  if (content != NULL)
	    RA::Debug("RA::ServerSideKeyGen", "response from DRM error status %ld", s);
	  else
	    RA::Debug("RA::ServerSideKeyGen", "response from DRM no content");
    }

 loser:
    if (desKey_s != NULL)
      PR_Free(desKey_s);

    if (decodeKey != NULL) {
      delete decodeKey;
    }

    if (wrappedDESKey_s != NULL)
      PR_Free(wrappedDESKey_s);

    if (drmConn != NULL)
      RA::ReturnDRMConn(drmConn);

    if (response != NULL) {
      if (content != NULL)
	response->freeContent();
      delete response;
    }

    if (ra_pb != NULL) {
      delete ra_pb;
    }

}


#define DES2_WORKAROUND
#define MAX_BODY_LEN 4096

PK11SymKey *RA::ComputeSessionKey(RA_Session *session,
                                  Buffer &CUID,
                                  Buffer &keyInfo,
                                  Buffer &card_challenge,
                                  Buffer &host_challenge,
                                  Buffer **host_cryptogram,
                                  Buffer &card_cryptogram,
                                  PK11SymKey **encSymKey,
                                  char** drm_desKey_s,
                                  char** kek_desKey_s,
                                  char** keycheck_s,
                                  const char *connId)
{
    PK11SymKey *symKey = NULL;
    PK11SymKey *symKey24 = NULL;
    PK11SymKey *encSymKey24 = NULL;
    PK11SymKey *transportKey = NULL;
    PK11SymKey *encSymKey16 = NULL;
    char body[MAX_BODY_LEN];
    char configname[256];
    char * cardc = NULL;
    char * hostc = NULL;
    char * cardCrypto = NULL;
    char * cuid = NULL;
    char * keyinfo =  NULL;
    PSHttpResponse *response = NULL;
    HttpConnection *tksConn = NULL;
    RA_pblock *ra_pb = NULL;
    SECItem *SecParam = PK11_ParamFromIV(CKM_DES3_ECB, NULL);
    char* transportKeyName = NULL;

    RA::Debug(LL_PER_PDU, "Start ComputeSessionKey", "");
    tksConn = RA::GetTKSConn(connId);
    if (tksConn == NULL) {
        RA::Error(LL_PER_PDU, "RA::ComputeSessionKey", "Failed to get TKSConnection %s", connId);
        return NULL;
    } else {
        int currRetries = 0;
        ConnectionInfo *connInfo = tksConn->GetFailoverList();

	PR_snprintf((char *) configname, 256, "conn.%s.keySet", connId);
	const char *keySet = RA::GetConfigStore()->GetConfigAsString(configname, "defKeySet");
	// is serversideKeygen on?
	PR_snprintf((char *) configname, 256, "conn.%s.serverKeygen", connId);
	bool serverKeygen = RA::GetConfigStore()->GetConfigAsBool(configname, false);
	if (serverKeygen)
	  RA::Debug(LL_PER_PDU, "RA::ComputeSessionKey", "serverKeygen for %s is on", connId);
	else
	  RA::Debug(LL_PER_PDU, "RA::ComputeSessionKey", "serverKeygen for %s is off", connId);

        cardc = Util::SpecialURLEncode(card_challenge);
        hostc = Util::SpecialURLEncode(host_challenge);
        cardCrypto = Util::SpecialURLEncode(card_cryptogram);
        cuid = Util::SpecialURLEncode(CUID);
        keyinfo = Util::SpecialURLEncode(keyInfo);

        if ((cardc == NULL) || (hostc == NULL) || (cardCrypto == NULL) ||
          (cuid == NULL) || (keyinfo == NULL))
	    goto loser;

        PR_snprintf((char *)body, MAX_BODY_LEN, 
          "serversideKeygen=%s&CUID=%s&card_challenge=%s&host_challenge=%s&KeyInfo=%s&card_cryptogram=%s&keySet=%s", serverKeygen? "true":"false", cuid, 
          cardc, hostc, keyinfo, cardCrypto, keySet);

        PR_snprintf((char *)configname, 256, "conn.%s.servlet.computeSessionKey", connId);
        const char *servletID = GetConfigStore()->GetConfigAsString(configname);
        int tks_curr = RA::GetCurrentIndex(tksConn);
        response = tksConn->getResponse(tks_curr, servletID, body);
        char **hostport = connInfo->GetHostPortList();
        if (response == NULL)
            RA::Debug(LL_PER_PDU, "The computeSessionKey response from TKS ", 
              "at %s is NULL.", hostport[tks_curr]);
        else 
            RA::Debug(LL_PER_PDU, "The computeSessionKey response from TKS ", 
              "at %s is not NULL.", hostport[tks_curr]);

        while (response == NULL) {
            RA::Failover(tksConn, connInfo->GetHostPortListLen());

            tks_curr = RA::GetCurrentIndex(tksConn);
            RA::Debug(LL_PER_PDU, "RA is reconnecting to TKS ", 
              "at %s for computeSessionKey.", hostport[tks_curr]);

            if (++currRetries >= tksConn->GetNumOfRetries()) {
                RA::Debug("Used up all the retries in ComputeSessionKey. Response is NULL","");
                RA::Error("RA::ComputeSessionKey","Failed connecting to TKS after %d retries", currRetries);

                goto loser;
            }
            response = tksConn->getResponse(tks_curr, servletID, body); 
        }

        RA::Debug(LL_PER_PDU, "ComputeSessionKey Response is not ","NULL");
        char * content = response->getContent();

	PK11SlotInfo *slot = PK11_GetInternalKeySlot();

        if (content != NULL) {
	  Buffer *status_b;

	  char *status_s, *sessionKey_s, *encSessionKey_s, *hostCryptogram_s;
	  int status;

      /* strip the http header */
      /* raidzilla 57722: strip the HTTP header and just pass
         name value pairs into the pblock parsing code.
       */
      RA::Debug("RA::Engine", "Pre-processing content '%s", content);
      char *cx = content;
      while (cx[0] != '\0' && (!(cx[0] == '\r' && cx[1] == '\n' && 
                 cx[2] == '\r' && cx[3] == '\n')))
      {
          cx++;
      }
      if (cx[0] != '\0') {
          cx+=4;
      }
      RA::Debug("RA::Engine", "Post-processing content '%s", cx);
	  ra_pb = ( RA_pblock * ) session->create_pblock(cx);
	  if (ra_pb == NULL) {
	    RA::Debug(LL_PER_PDU, "RA:ComputeSessionKey", "fail no ra_pb");
	    goto loser;
	  }

	status_b = ra_pb->find_val(TKS_RESPONSE_STATUS);
	if (status_b == NULL) {
	  status = 4;
	    RA::Error(LL_PER_SERVER, "RA:ComputeSessionKey", "Bad TKS Connection. Please make sure TKS is accessible by TPS.");
	    RA::Debug(LL_PER_PDU, "RA:ComputeSessionKey", "fail no status");
      goto loser;
	  // return NULL;
	}
	else {
	  status_s = status_b->string();
	  status = atoi(status_s);
          if (status_s != NULL) {
              PR_Free(status_s);
          }
	}

        // Now unwrap the session keys with shared secret transport key

        PR_snprintf((char *)configname, 256, "conn.%s.tksSharedSymKeyName", connId);

        transportKeyName = (char *)  m_cfg->GetConfigAsString(configname, TRANSPORT_KEY_NAME);

        RA::Debug(LL_PER_PDU,"RA:ComputeSessionKey","Shared Secret key name: %s.", transportKeyName);

        transportKey = FindSymKeyByName( slot,  transportKeyName);

        if ( transportKey == NULL ) {
            RA::Debug(LL_PER_PDU,"RA::ComputeSessionKey","fail getting transport key");
            goto loser; 
        }      

	sessionKey_s = ra_pb->find_val_s(TKS_RESPONSE_SessionKey);
	if (sessionKey_s == NULL) {
	  RA::Debug(LL_PER_PDU, "RA:ComputeSessionKey", "fail no sessionKey_b");
	  goto loser;
	}

	RA::Debug(LL_PER_PDU, "RA:ComputeSessionKey", "mac session key=%s", sessionKey_s);
	Buffer *decodeKey = Util::URLDecode(sessionKey_s);

	RA::Debug(LL_PER_PDU, "RA:ComputeSessionKey", "decodekey len=%d",decodeKey->size());

	BYTE *keyData = (BYTE *)*decodeKey;
        SECItem wrappeditem = {siBuffer , keyData, 16 };

        symKey = PK11_UnwrapSymKey(transportKey,
                          CKM_DES3_ECB,SecParam, &wrappeditem,
                          CKM_DES3_ECB,
                          CKA_UNWRAP,
                          16);

        if ( symKey ) {
           symKey24 = CreateDesKey24Byte(slot, symKey);
        }

	if( decodeKey != NULL ) {
	  delete decodeKey;
	  decodeKey = NULL;
	}
	if (symKey24 == NULL)
	  RA::Debug(LL_PER_PDU, "RA:ComputeSessionKey", "MAC Session key is NULL");


	encSessionKey_s = ra_pb->find_val_s(TKS_RESPONSE_EncSessionKey);
	if (encSessionKey_s == NULL) {
	  RA::Debug(LL_PER_PDU, "RA:ComputeSessionKey", "fail no encSessionKey_b");
	  goto loser;
	}

	RA::Debug(LL_PER_PDU, "RA:ComputeSessionKey", "encSessionKey=%s", encSessionKey_s);
	Buffer *decodeEncKey = Util::URLDecode(encSessionKey_s);

	RA::Debug(LL_PER_PDU, "RA:ComputeSessionKey",
		  "decodeEnckey len=%d",decodeEncKey->size());

	BYTE *EnckeyData = (BYTE *)*decodeEncKey;
        wrappeditem.data = (unsigned char *) EnckeyData;
        wrappeditem.len = 16; 

        encSymKey16 = PK11_UnwrapSymKey(transportKey,
                          CKM_DES3_ECB,SecParam, &wrappeditem,
                          CKM_DES3_ECB,
                          CKA_UNWRAP,
                          16);

        if ( encSymKey16 ) {
           encSymKey24 = CreateDesKey24Byte(slot, encSymKey16);
        }

        *encSymKey = encSymKey24;

	if( decodeEncKey != NULL ) {
	  delete decodeEncKey;
	  decodeEncKey = NULL;
	}

	if (encSymKey24 == NULL)
	  RA::Debug(LL_PER_PDU, "RA:ComputeSessionKey", "encSessionKey is NULL");

	if (serverKeygen) {
	  char * tmp= NULL;
	  tmp = ra_pb->find_val_s(TKS_RESPONSE_DRM_Trans_DesKey);
	  if (tmp == NULL) {
	    RA::Debug(LL_PER_PDU, "RA:ComputeSessionKey", "drm_desKey not retrieved");
	    RA::Error(LL_PER_PDU, "RA:ComputeSessionKey", "drm_desKey not retrieved");
	    goto loser;
	  } else {
	    *drm_desKey_s = PL_strdup(tmp);
	  }
	  // wrapped des key is to be sent to DRM "as is"
	  // thus should not be touched
	  RA::Debug(LL_PER_PDU, "RA:ComputeSessionKey", "drm_desKey=%s", *drm_desKey_s );

	  tmp = ra_pb->find_val_s(TKS_RESPONSE_KEK_DesKey);
	  if (tmp == NULL) {
	    RA::Debug(LL_PER_PDU, "RA:ComputeSessionKey", "kek-wrapped desKey not retrieved");
	    RA::Error(LL_PER_PDU, "RA:ComputeSessionKey", "kek-wrapped desKey not retrieved");
	    goto loser;
	  } else {
	    *kek_desKey_s = PL_strdup(tmp);
	  }
	  RA::Debug(LL_PER_PDU, "RA:ComputeSessionKey", "kek_desKey=%s", *kek_desKey_s );


	  tmp = ra_pb->find_val_s("keycheck");
	  if (tmp == NULL) {
	    RA::Debug(LL_PER_PDU, "RA:ComputeSessionKey", "keycheck not retrieved");
	    RA::Error(LL_PER_PDU, "RA:ComputeSessionKey", "keycheck not retrieved");
	    goto loser;
	  } else {
	    *keycheck_s = PL_strdup(tmp);
	  }
	}// serversideKeygen

	hostCryptogram_s = ra_pb->find_val_s(TKS_RESPONSE_HostCryptogram);
	if (hostCryptogram_s == NULL)
	  goto loser;

                        RA::Debug(LL_PER_PDU, "RA:ComputeSessionKey", "hostC=%s", hostCryptogram_s);
                        *host_cryptogram = Util::URLDecode(hostCryptogram_s);
	} // if content != NULL

    } // else tksConn != NULL
        RA::Debug(LL_PER_PDU, "finish ComputeSessionKey", "");


 loser:
	if (tksConn != NULL) {
            RA::ReturnTKSConn(tksConn);
	}
    if( cardc != NULL ) {
        PR_Free( cardc );
        cardc = NULL;
    }
    if( hostc != NULL ) {
        PR_Free( hostc );
        hostc = NULL;
    }
    if( cuid != NULL ) {
        PR_Free( cuid );
        cuid = NULL;
    }
    if( keyinfo != NULL ) {
        PR_Free( keyinfo );
        keyinfo = NULL;
    }
    if (cardCrypto != NULL) {
        PR_Free( cardCrypto );
        cardCrypto = NULL;
    }

    if( response != NULL ) {
        response->freeContent();
        delete response;
        response = NULL;
    }

    if ( SecParam != NULL ) {
         SECITEM_FreeItem(SecParam, PR_TRUE);
         SecParam = NULL;
    }

    if (ra_pb != NULL) {
      delete ra_pb;
    }
    
    if ( symKey != NULL ) {
        PK11_FreeSymKey( symKey );
        symKey = NULL;
    }
 
    if ( encSymKey16 != NULL ) {
        PK11_FreeSymKey( encSymKey16 );
        encSymKey16 = NULL;
    }

	// in production, if TKS is unreachable, symKey will be NULL,
	// and this will signal error to the caller.
	return symKey24;
}

Buffer *RA::ComputeHostCryptogram(Buffer &card_challenge, 
		Buffer &host_challenge)
{ 
	/* hardcoded enc auth key */
	BYTE enc_auth_key[16] = {
		0x40, 0x41, 0x42, 0x43, 
		0x44, 0x45, 0x46, 0x47, 
		0x48, 0x49, 0x4a, 0x4b, 
		0x4c, 0x4d, 0x4e, 0x4f 
	};
	Buffer input = Buffer(16, (BYTE)0);
	int i;
	Buffer icv = Buffer(8, (BYTE)0);
	Buffer *output = new Buffer(8, (BYTE)0);
	BYTE *cc = (BYTE*)card_challenge;
	int cc_len = card_challenge.size();
	BYTE *hc = (BYTE*)host_challenge;
	int hc_len = host_challenge.size();

	/* copy card and host challenge into input buffer */
	for (i = 0; i < 8; i++) {
		((BYTE*)input)[i] = cc[i];
	}
	for (i = 0; i < 8; i++) {
		((BYTE*)input)[8+i] = hc[i];
	}

	PK11SymKey *key = Util::DeriveKey(
		Buffer(enc_auth_key, 16), Buffer(hc, hc_len), 
		Buffer(cc, cc_len));
	Util::ComputeMAC(key, input, icv, *output);

	return output;
}

TPS_PUBLIC void RA::DebugBuffer(const char *func_name, const char *prefix, Buffer *buf)
{
	RA::DebugBuffer(LL_PER_CONNECTION, func_name, prefix, buf);
}

void RA::DebugBuffer(RA_Log_Level level, const char *func_name, const char *prefix, Buffer *buf)
{
    int i;
    PRTime now;
    const char* time_fmt = "%Y-%m-%d %H:%M:%S";
    char datetime[1024]; 
    PRExplodedTime time;
    BYTE *data = *buf;
    int sum = 0;
	PRThread *ct;

    if ((m_debug_log == NULL) || (!m_debug_log->isOpen())) 
        return;
    if ((int) level >= m_debug_log_level)
		return;
    PR_Lock(m_debug_log_lock);
    now = PR_Now();
    PR_ExplodeTime(now, PR_LocalTimeParameters, &time);
    PR_FormatTimeUSEnglish(datetime, 1024, time_fmt, &time);
    ct = PR_GetCurrentThread();
    m_debug_log->printf("[%s] %x %s - ", datetime, ct, func_name);
    m_debug_log->printf("%s (length='%d')", prefix, buf->size());
    m_debug_log->printf("\n");
    m_debug_log->printf("[%s] %x %s - ", datetime, ct, func_name);
    for (i=0; i<(int)buf->size(); i++) {
        m_debug_log->printf("%02x ", (unsigned char)data[i]);
        sum++; 
	if (sum == 10) {
    		m_debug_log->printf("\n");
                m_debug_log->printf("[%s] %x %s - ", datetime, ct, func_name);
                sum = 0;
	}
    }
    m_debug_log->write("\n");
    PR_Unlock(m_debug_log_lock);
}

TPS_PUBLIC void RA::Debug (const char *func_name, const char *fmt, ...)
{ 
	va_list ap; 
	va_start(ap, fmt); 
	RA::DebugThis(LL_PER_SERVER, func_name, fmt, ap);
	va_end(ap); 
}

TPS_PUBLIC void RA::Debug (RA_Log_Level level, const char *func_name, const char *fmt, ...)
{ 
	va_list ap; 
	va_start(ap, fmt); 
	RA::DebugThis(level, func_name, fmt, ap);
	va_end(ap); 
}



void RA::DebugThis (RA_Log_Level level, const char *func_name, const char *fmt, va_list ap)
{ 
	PRTime now;
        const char* time_fmt = "%Y-%m-%d %H:%M:%S";
        char datetime[1024]; 
        PRExplodedTime time;
	PRThread *ct;

 	if ((m_debug_log == NULL) || (!m_debug_log->isOpen())) 
		return;
	if ((int) level >= m_debug_log_level)
		return;
	PR_Lock(m_debug_log_lock);
	now = PR_Now();
	ct = PR_GetCurrentThread();
        PR_ExplodeTime(now, PR_LocalTimeParameters, &time);
	PR_FormatTimeUSEnglish(datetime, 1024, time_fmt, &time);
	m_debug_log->printf("[%s] %x %s - ", datetime, ct, func_name);
	m_debug_log->vfprintf(fmt, ap); 
	m_debug_log->write("\n");
	PR_Unlock(m_debug_log_lock);
}

TPS_PUBLIC void RA::Audit (const char *func_name, const char *fmt, ...)
{ 
        if (!RA::IsAuditEventSelected(func_name))
            return;

	va_list ap; 
	va_start(ap, fmt); 
	RA::AuditThis (LL_PER_SERVER, func_name, fmt, ap);
	va_end(ap); 
	va_start(ap, fmt); 
//	RA::DebugThis (LL_PER_SERVER, func_name, fmt, ap);
	va_end(ap); 
}

TPS_PUBLIC void RA::Audit (RA_Log_Level level, const char *func_name, const char *fmt, ...)
{ 
        if (!RA::IsAuditEventSelected(func_name))
            return;

	va_list ap; 
	va_start(ap, fmt); 
	RA::AuditThis (level, func_name, fmt, ap);
	va_end(ap); 
	va_start(ap, fmt); 
	RA::DebugThis (level, func_name, fmt, ap);
	va_end(ap); 
}

void RA::AuditThis (RA_Log_Level level, const char *func_name, const char *fmt, va_list ap)
{ 
	PRTime now;
        const char* time_fmt = "%Y-%m-%d %H:%M:%S";
        char datetime[1024]; 
        PRExplodedTime time;
	PRThread *ct;
        char *message_p1 = NULL;
        char *message_p2 = NULL;
        int nbytes;
        int status;

        if (!m_audit_enabled) return;
 
        if ((m_audit_log == NULL) || (!m_audit_log->isOpen()) || (m_audit_log_buffer == NULL))
		return;
	if ((int) level >= m_audit_log_level)
		return;

	PR_EnterMonitor(m_audit_log_monitor);
	now = PR_Now();
        PR_ExplodeTime(now, PR_LocalTimeParameters, &time);
	PR_FormatTimeUSEnglish(datetime, 1024, time_fmt, &time);
	ct = PR_GetCurrentThread();

        message_p1 = PR_smprintf("[%s] %x [AuditEvent=%s]", datetime, ct, func_name);
	message_p2 = PR_vsmprintf(fmt, ap); 

        /* write out the message first */
        NSSUTF8 *audit_msg = PR_smprintf("%s%s\n", message_p1, message_p2);
        nbytes = (unsigned) PL_strlen((const char*) audit_msg);
        if ((m_bytes_unflushed + nbytes) >= m_buffer_size) {
            FlushAuditLogBuffer();
            status = m_audit_log->write(audit_msg); 
            if (status != PR_SUCCESS) {
                m_audit_log->get_context()->LogError( "RA::AuditThis",
                      __LINE__,
                      "AuditThis: Failure to write to the audit log.  Shutting down ..."); 
                _exit(APEXIT_CHILDFATAL);
            }
            m_audit_log->setSigned(false);

            if (m_audit_signed) SignAuditLog(audit_msg);
        } else {
            PL_strcat(m_audit_log_buffer, audit_msg);
            m_bytes_unflushed += nbytes; 
        }

        PR_Free(message_p1);
        PR_Free(message_p2);

        if (audit_msg)
            PR_Free(audit_msg);

        PR_ExitMonitor(m_audit_log_monitor);

}

TPS_PUBLIC void RA::FlushAuditLogBuffer()
{
    int status;

    if (!m_audit_enabled) return;

    PR_EnterMonitor(m_audit_log_monitor);
    if ((m_bytes_unflushed > 0) && (m_audit_log_buffer != NULL) && (m_audit_log != NULL)) { 
        status = m_audit_log->write(m_audit_log_buffer);
        if (status != PR_SUCCESS) {
            m_audit_log->get_context()->LogError( "RA::FlushAuditLogBuffer",
                  __LINE__,
                  "RA::FlushAuditLogBuffer: Failure to write to the audit log.  Shutting down ...");
            _exit(APEXIT_CHILDFATAL);
        }
        m_audit_log->setSigned(false);
        if (m_audit_signed) {
            SignAuditLog((NSSUTF8 *) m_audit_log_buffer);
        }
        m_bytes_unflushed=0;
        PR_snprintf((char *) m_audit_log_buffer, m_buffer_size, "");
    }
    PR_ExitMonitor(m_audit_log_monitor);
}

TPS_PUBLIC void RA::SignAuditLog(NSSUTF8 * audit_msg)
{
    char *audit_sig_msg = NULL;
    char sig[4096];
    int status;

    if (!m_audit_enabled) return;

    PR_EnterMonitor(m_audit_log_monitor);
    audit_sig_msg = GetAuditSigningMessage(audit_msg);
    
    if (audit_sig_msg != NULL) {
        PR_snprintf(sig, 4096, "%s\n", audit_sig_msg);
        status = m_audit_log->write(sig); 
        if (status != PR_SUCCESS) {
            m_audit_log->get_context()->LogError( "RA::SignAuditLog",
                  __LINE__,
                  "SignAuditLog: Failure to write to the audit log.  Shutting down ..");
            _exit(APEXIT_CHILDFATAL);
        }
        if (m_last_audit_signature != NULL) {
            PR_Free( m_last_audit_signature );
        }
        m_last_audit_signature = PL_strdup(audit_sig_msg);
        m_audit_log->setSigned(true);
        
        PR_Free(audit_sig_msg);
    }
    PR_ExitMonitor(m_audit_log_monitor);
}

TPS_PUBLIC void RA::ra_free_values(struct berval **values) 
{
    free_values(values, 1);
}
     
/* sign audit_msg and last signature 
   returns char* - must be freed by caller */
TPS_PUBLIC char * RA::GetAuditSigningMessage(const NSSUTF8 * audit_msg)
{
        PRTime now;
        const char* time_fmt = "%Y-%m-%d %H:%M:%S";
        char datetime[1024];
        PRExplodedTime time;
        PRThread *ct;
        SECStatus rv;

        SECItem signedResult;
        NSSUTF8 *sig_b64 = NULL;
        NSSUTF8 *out_sig_b64 = NULL;
        SGNContext *sign_ctxt=NULL;
        char *audit_sig_msg = NULL;
        char sig[4096];

        now = PR_Now();
        PR_ExplodeTime(now, PR_LocalTimeParameters, &time);
        PR_FormatTimeUSEnglish(datetime, 1024, time_fmt, &time);
        ct = PR_GetCurrentThread();

        if (m_audit_signed==true) {
            sign_ctxt = SGN_NewContext(m_audit_signAlgTag, m_audit_signing_key);
            if( SGN_Begin(sign_ctxt) != SECSuccess ) {
                RA::Debug("RA:: SignAuditLog", "SGN_Begin failed");
                goto loser;
            }

            if (m_last_audit_signature != NULL) {
                RA::Debug("RA:: SignAuditLog", "m_last_audit_signature == %s",
                       m_last_audit_signature);

                PR_snprintf(sig, 4096, "%s\n", m_last_audit_signature);
                rv = SGN_Update( (SGNContext*)sign_ctxt,
                        (unsigned char *) sig, 
                        (unsigned)PL_strlen((const char*)sig));
                if (rv != SECSuccess) {
                    RA::Debug("RA:: SignAuditLog", "SGN_Update failed");
                    goto loser;
                }

            } else {
                RA::Debug("RA:: SignAuditLog", "m_last_audit_signature == NULL");
            }

            /* make sign the UTF-8 bytes later */

            if( SGN_Update( (SGNContext*)sign_ctxt,
                        (unsigned char *) audit_msg,
                        (unsigned)PL_strlen((const char*)audit_msg)) != SECSuccess) {
                RA::Debug("RA:: SignAuditLog", "SGN_Update failed");
                goto loser;
            }

            if( SGN_End(sign_ctxt, &signedResult) != SECSuccess) {
                RA::Debug("RA:: SignAuditLog", "SGN_End failed");
                goto loser;
            }

            sig_b64 = NSSBase64_EncodeItem(NULL, NULL, 0, &signedResult);
            if (sig_b64 == NULL) {
                RA::Debug("RA:: SignAuditLog", "NSSBase64_EncodeItem failed");
                goto loser;
            }

            /* get rid of the carriage return line feed */
            int sig_len = PL_strlen(sig_b64);
            out_sig_b64 =  (char *) PORT_Alloc (sig_len);
            if (out_sig_b64 == NULL) {
                RA::Debug("RA:: SignAuditLog", "PORT_Alloc for out_sig_b64 failed");
                goto loser;
            }
            int i = 0;
            char *p = sig_b64;
            for (i = 0; i< sig_len; i++, p++) {
                if ((*p!=13) && (*p!= 10)) {
                    out_sig_b64[i] = *p;
                } else {
                    i--;
                    continue;
                }
            }

            /*
             * write out the signature
             */
            audit_sig_msg = PR_smprintf(AUDIT_SIG_MSG_FORMAT,
                 datetime, ct, "AUDIT_LOG_SIGNING",
                 "System", "Success", out_sig_b64);

        }

loser:
        if (m_audit_signed==true) {
            if (sign_ctxt)
                SGN_DestroyContext(sign_ctxt, PR_TRUE);
            if (sig_b64)
                PR_Free(sig_b64);
            if (out_sig_b64)
                PR_Free(out_sig_b64);
            SECITEM_FreeItem(&signedResult, PR_FALSE);
        }

        return audit_sig_msg;
} 

TPS_PUBLIC void RA::SetFlushInterval(int interval)
{
    char interval_str[512];
    int status;
    char error_msg[512];

    RA::Debug("RA::SetFlushInterval", "Setting flush interval to %d seconds", interval);
    m_flush_interval = interval;

    // Interrupt the flush thread to set new interval
    // Get monitor so as not to interrupt the flush thread during flushing

    PR_EnterMonitor(m_audit_log_monitor);
    PR_Interrupt(m_flush_thread);
    PR_ExitMonitor(m_audit_log_monitor);
    
    PR_snprintf((char *) interval_str, 512, "%d", interval);
    m_cfg->Add(CFG_AUDIT_FLUSH_INTERVAL, interval_str);
    status = m_cfg->Commit(false, error_msg, 512);
    if (status != 0) {
        RA::Debug("RA:SetFlushInterval", error_msg);
    }
}

TPS_PUBLIC void RA::SetBufferSize(int size)
{
    char * new_buffer;
    char size_str[512];
    int status;
    char error_msg[512];

    RA::Debug("RA::SetBufferSize", "Setting buffer size to %d bytes", size);

    PR_EnterMonitor(m_audit_log_monitor);
    FlushAuditLogBuffer();
    if (m_audit_log_buffer != NULL) {
        new_buffer = (char *) PR_Realloc(m_audit_log_buffer, size);
        m_audit_log_buffer = new_buffer;
    } else {
        m_audit_log_buffer = (char *) PR_Malloc(size);
    }
    m_buffer_size = size;
    PR_ExitMonitor(m_audit_log_monitor);

    PR_snprintf((char *) size_str, 512, "%d", size);
    m_cfg->Add(CFG_AUDIT_BUFFER_SIZE, size_str);

    status = m_cfg->Commit(false, error_msg, 512);
    if (status != 0) {
        RA::Debug("RA:SetFlushInterval", error_msg);
    }
}


TPS_PUBLIC void RA::Error (const char *func_name, const char *fmt, ...)
{ 
	va_list ap; 
	va_start(ap, fmt); 
	RA::ErrorThis(LL_PER_SERVER, func_name, fmt, ap);
	va_end(ap); 
	va_start(ap, fmt); 
	RA::DebugThis(LL_PER_SERVER, func_name, fmt, ap);
	va_end(ap); 
}

TPS_PUBLIC void RA::Error (RA_Log_Level level, const char *func_name, const char *fmt, ...)
{ 
	va_list ap; 
	va_start(ap, fmt); 
	RA::ErrorThis(level, func_name, fmt, ap);
	va_end(ap); 
	va_start(ap, fmt); 
	RA::DebugThis(level, func_name, fmt, ap);
	va_end(ap); 
}

void RA::ErrorThis (RA_Log_Level level, const char *func_name, const char *fmt, va_list ap)
{ 
	PRTime now;
        const char* time_fmt = "%Y-%m-%d %H:%M:%S";
        char datetime[1024]; 
        PRExplodedTime time;
	PRThread *ct;

 	if ((m_error_log == NULL) || (!m_error_log->isOpen()))
		return;
	if ((int) level >= m_error_log_level)
		return;
	PR_Lock(m_error_log_lock);
	now = PR_Now();
	ct = PR_GetCurrentThread();
        PR_ExplodeTime(now, PR_LocalTimeParameters, &time);
	PR_FormatTimeUSEnglish(datetime, 1024, time_fmt, &time);
	m_error_log->printf("[%s] %x %s - ", datetime, ct, func_name);
	m_error_log->vfprintf(fmt, ap); 
	m_error_log->write("\n");
	PR_Unlock(m_error_log_lock);
}

TPS_PUBLIC void RA::update_signed_audit_selected_events(char *new_selected)
{
    char *tmp = NULL;
    m_cfg->Add(CFG_AUDIT_SELECTED_EVENTS, new_selected);

    tmp = m_signedAuditSelectedEvents;
    m_signedAuditSelectedEvents = PL_strdup(new_selected);
    PL_strfree(tmp);
}

TPS_PUBLIC void RA::update_signed_audit_enable(const char *enable)
{
   m_cfg->Add(CFG_AUDIT_ENABLE, enable);
}


TPS_PUBLIC void RA::update_signed_audit_log_signing(const char *enable)
{
   m_cfg->Add(CFG_AUDIT_SIGNED, enable);
}

TPS_PUBLIC int RA::ra_find_tus_certificate_entries_by_order_no_vlv (char *filter,
  LDAPMessage **result, int order) 
{
    return find_tus_certificate_entries_by_order_no_vlv(filter, result, order);
}

TPS_PUBLIC int RA::ra_find_tus_certificate_entries_by_order (char *filter,
  int max, LDAPMessage **result, int order) 
{
    return find_tus_certificate_entries_by_order(filter, max, result, order);
}

TPS_PUBLIC CERTCertificate **RA::ra_get_certificates(LDAPMessage *e) {
    return get_certificates(e);
}

TPS_PUBLIC LDAPMessage *RA::ra_get_first_entry(LDAPMessage *e) {
    return get_first_entry(e);
}

TPS_PUBLIC LDAPMessage *RA::ra_get_next_entry(LDAPMessage *e) {
    return get_next_entry(e);
}

TPS_PUBLIC struct berval **RA::ra_get_attribute_values(LDAPMessage *e, const char *p) {
    return get_attribute_values(e, p);
}

TPS_PUBLIC char *RA::ra_get_cert_cn(LDAPMessage *entry) {
    return get_cert_cn(entry);
}

TPS_PUBLIC char *RA::ra_get_cert_attr_byname(LDAPMessage *entry, const char *name) {
    return get_cert_attr_byname(entry, name);
}

TPS_PUBLIC char *RA::ra_get_cert_status(LDAPMessage *entry) {
    return get_cert_status(entry);
}

TPS_PUBLIC char *RA::ra_get_cert_type(LDAPMessage *entry) {
    return get_cert_type(entry);
}

TPS_PUBLIC char *RA::ra_get_cert_serial(LDAPMessage *entry) {
    return get_cert_serial(entry);
}

TPS_PUBLIC char *RA::ra_get_cert_issuer(LDAPMessage *entry) {
    return get_cert_issuer(entry);
}

TPS_PUBLIC char *RA::ra_get_token_reason(LDAPMessage *msg) {
    return get_token_reason(msg);
}

TPS_PUBLIC int RA::ra_get_number_of_entries(LDAPMessage *ldapResult) {
    return get_number_of_entries(ldapResult);
}

TPS_PUBLIC int RA::ra_find_tus_token_entries_no_vlv(char *filter, 
  LDAPMessage **ldapResult, int num) 
{
    return find_tus_token_entries_no_vlv(filter, ldapResult, num);
}

TPS_PUBLIC int RA::ra_find_tus_token_entries(char *filter, int maxReturns,
  LDAPMessage **ldapResult, int num) 
{
    return find_tus_token_entries(filter, maxReturns, ldapResult, num);
}

TPS_PUBLIC char *RA::ra_get_token_userid(char *cuid)
{
    return get_token_userid(cuid);
}

TPS_PUBLIC void RA::ra_tus_print_integer(char *out, SECItem *data)
{
    tus_print_integer(out, data);
}

TPS_PUBLIC int RA::ra_delete_certificate_entry(LDAPMessage* e) 
{
   char *dn = get_dn(e);
   int rc = LDAP_SUCCESS;

   if (dn != NULL) {
       rc = delete_tus_general_db_entry(dn);
       if (rc != LDAP_SUCCESS) {
           RA::Debug("RA::delete_certificate_entry", 
                     "Failed to remove certificate entry: %s", dn);
       }
       PL_strfree(dn);
       dn = NULL;
   }
   return rc;
}

int RA::Failover(HttpConnection *&conn, int len) {
    int rc = 0;
    if (m_pod_enable) {
        PR_Lock(m_pod_lock);
        if (++m_pod_curr >= len) 
            m_pod_curr = 0;
        HttpConnection *conn = NULL;
        for (int i=0; i<m_caConns_len; i++) {
            conn = m_caConnection[i];
            RA::SetCurrentIndex(conn, m_pod_curr);
            conn = m_drmConnection[i];
            RA::SetCurrentIndex(conn, m_pod_curr);
            conn = m_tksConnection[i];
            RA::SetCurrentIndex(conn, m_pod_curr);
        }
        PR_Unlock(m_pod_lock);
    } else {
        if (conn != NULL) {
            int curr = RA::GetCurrentIndex(conn);
            if (++curr >= len)
                curr = 0;
            RA::SetCurrentIndex(conn, curr);
        } else
            rc = -1;
    }
    return rc;
}

PK11SymKey *RA::FindSymKeyByName( PK11SlotInfo *slot, char *keyname) {
char       *name       = NULL;
    PK11SymKey *foundSymKey= NULL;
    PK11SymKey *firstSymKey= NULL;
    PK11SymKey *sk  = NULL;
    PK11SymKey *nextSymKey = NULL;
    secuPWData  pwdata;

    pwdata.source   = secuPWData::PW_NONE;
    pwdata.data     = (char *) NULL;
    if (keyname == NULL)
    {
        goto cleanup;
    }
    if (slot== NULL)
    {
        goto cleanup;
    }
    /* Initialize the symmetric key list. */
    firstSymKey = PK11_ListFixedKeysInSlot( slot , NULL, ( void *) &pwdata );
    /* scan through the symmetric key list for a key matching our nickname */
    sk = firstSymKey;
    while( sk != NULL )
    {
        /* get the nickname of this symkey */
        name = PK11_GetSymKeyNickname( sk );

        /* if the name matches, make a 'copy' of it */
        if ( name != NULL && !strcmp( keyname, name ))
        {
            if (foundSymKey == NULL)
            {
                foundSymKey = PK11_ReferenceSymKey(sk);
            }
            PORT_Free(name);
        }

        sk = PK11_GetNextSymKey( sk );
    }

    /* We're done with the list now, let's free all the keys in it
       It's okay to free our key, because we made a copy of it */

    sk = firstSymKey;
    while( sk != NULL )
    {
        nextSymKey = PK11_GetNextSymKey(sk);
        PK11_FreeSymKey(sk);
        sk = nextSymKey;
    }

    cleanup:
    return foundSymKey;
}

PK11SymKey *RA::CreateDesKey24Byte(PK11SlotInfo *slot, PK11SymKey *origKey)
{
    PK11SymKey *newKey = NULL;
    PK11SymKey *firstEight = NULL;
    PK11SymKey *concatKey = NULL;
    PK11SymKey *internalOrigKey = NULL;
    CK_ULONG bitPosition = 0;
    SECItem paramsItem = { siBuffer, NULL, 0 };
    CK_OBJECT_HANDLE keyhandle = 0;
    RA::Debug("RA::CreateDesKey24Byte",
                "entering.");

    PK11SlotInfo *internal = PK11_GetInternalSlot();
    if ( slot == NULL || origKey == NULL || internal == NULL)
        goto loser;

    if( internal != slot ) {  //Make sure we do this on the NSS Generic Crypto services because concatanation
                              // only works there.
        internalOrigKey = PK11_MoveSymKey( internal, CKA_ENCRYPT, 0, PR_FALSE, origKey );
    }
    // Extract first eight bytes from generated key into another key.
    bitPosition = 0;
    paramsItem.data = (CK_BYTE *) &bitPosition;
    paramsItem.len = sizeof bitPosition;

    if ( internalOrigKey)
        firstEight = PK11_Derive(internalOrigKey, CKM_EXTRACT_KEY_FROM_KEY, &paramsItem, CKA_ENCRYPT , CKA_DERIVE, 8);
    else 
        firstEight = PK11_Derive(origKey, CKM_EXTRACT_KEY_FROM_KEY, &paramsItem, CKA_ENCRYPT , CKA_DERIVE, 8);

    if (firstEight  == NULL ) {
         RA::Debug("RA::CreateDesKey24Byte",
                "error deriving 8 byte portion of key.");
        goto loser;
    }

    //Concatenate 8 byte key to the end of the original key, giving new 24 byte key
    keyhandle = PK11_GetSymKeyHandle(firstEight);

    paramsItem.data=(unsigned char *) &keyhandle;
    paramsItem.len=sizeof(keyhandle);

    if ( internalOrigKey ) {
        concatKey = PK11_Derive ( internalOrigKey , CKM_CONCATENATE_BASE_AND_KEY , &paramsItem ,CKM_DES3_ECB , CKA_DERIVE , 0);
    } else {
        concatKey = PK11_Derive ( origKey , CKM_CONCATENATE_BASE_AND_KEY , &paramsItem ,CKM_DES3_ECB , CKA_DERIVE , 0);
    }

    if ( concatKey == NULL ) {
        RA::Debug("RA::CreateDesKey24Byte",
                "error concatenating 8 bytes on end of key.");
        goto loser;
    }

    //Make sure we move this to the proper token, in case it got moved by NSS
    //during the derive phase.

    newKey =  PK11_MoveSymKey ( slot, CKA_ENCRYPT, 0, PR_FALSE, concatKey);

    if ( newKey == NULL ) {
        RA::Debug("RA::CreateDesKey24Byte",
                "error moving key to original slot.");
    }

loser:

    if ( concatKey != NULL ) {
        PK11_FreeSymKey( concatKey );
        concatKey = NULL;
    }

    if ( firstEight != NULL ) {
        PK11_FreeSymKey ( firstEight );
        firstEight = NULL;
    }

    if ( internalOrigKey != NULL ) {
       PK11_FreeSymKey ( internalOrigKey );
       internalOrigKey = NULL;
    }

    if ( internal != NULL ) {
       PK11_FreeSlot( internal); 
       internal = NULL;
    }

    return newKey;
}

bool RA::isAlgorithmECC(BYTE alg)
{
    bool result = false;

    if (alg == ALG_EC_F2M || alg == ALG_EC_FP)
       result = true;

    RA::Debug(LL_PER_SERVER, "RA::isAlgorithmECC", " alg: %d result: %d", alg, result);

    return result;
}
