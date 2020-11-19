/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information.
 *
 *    Copyright 2016-2017 (c) Fraunhofer IOSB (Author: Julius Pfrommer)
 *    Copyright 2017 (c) Stefan Profanter, fortiss GmbH
 *    Copyright 2019 (c) HMS Industrial Networks AB (Author: Jonas Green)
 */

#include <open62541/plugin/accesscontrol_default.h>
#include <open62541/server_config.h>

#ifdef UA_ENABLE_PAM
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#endif

/* Example access control management. Anonymous and username / password login.
 * The access rights are maximally permissive. */

typedef struct {
    UA_Boolean allowAnonymous;
    size_t usernamePasswordLoginSize;
    UA_UsernamePasswordLogin *usernamePasswordLogin;
} AccessControlContext;

#define ANONYMOUS_POLICY "open62541-anonymous-policy"
#define USERNAME_POLICY "open62541-username-policy"
const UA_String anonymous_policy = UA_STRING_STATIC(ANONYMOUS_POLICY);
const UA_String username_policy = UA_STRING_STATIC(USERNAME_POLICY);

/************************/
/* Access Control Logic */
/************************/

#ifdef UA_ENABLE_PAM

/* Service modules do not clean up responses if an error is returned.
 * Free responses here.
 */
static void
free_resp(int num_msg, struct pam_response *pr) {
    int i;
    struct pam_response *r = pr;
    if(pr == NULL)
        return;

    for(i = 0; i < num_msg; i++, r++) {

        if(r->resp) {
            /* clear before freeing -- may be a password */
            bzero(r->resp, strlen(r->resp));
            free(r->resp);
            r->resp = NULL;
        }
    }
    free(pr);
}

static int
convCallback(int num_msg, const struct pam_message **msg, struct pam_response **resp,
             void *appdata_ptr) {

    struct pam_response *aresp;
    int i;

    if(num_msg <= 0 || num_msg > PAM_MAX_NUM_MSG) {
        *resp = NULL;
        return (PAM_CONV_ERR);
    }

    if((*resp = aresp = (struct pam_response *)calloc(
            (size_t)num_msg, sizeof(struct pam_response))) == NULL)
        return (PAM_BUF_ERR);

    for(i = 0; i < num_msg; ++i) {

        /* bad message from service module */
        if(msg[i]->msg == NULL) {
            // TODO Log
            free_resp(i, aresp);
            *resp = NULL;
            return (PAM_CONV_ERR);
        }

        aresp[i].resp_retcode = 0;
        aresp[i].resp = NULL;
        switch(msg[i]->msg_style) {
            case PAM_PROMPT_ECHO_OFF:
            /*FALLTHROUGH*/
            case PAM_PROMPT_ECHO_ON:
                aresp[i].resp = strdup((char *)appdata_ptr);
                if(aresp[i].resp == NULL) {
                    free_resp(i, aresp);
                    *resp = NULL;
                    return (PAM_CONV_ERR);
                }
                break;
            case PAM_ERROR_MSG:
                // TODO Log Error msg
                if(aresp[i].resp == NULL) {
                    free_resp(i, aresp);
                    *resp = NULL;
                    return (PAM_CONV_ERR);
                }
                break;
            case PAM_TEXT_INFO:
                // TODO Log Info msg
                if(strlen(msg[i]->msg) > 0 &&
                   msg[i]->msg[strlen(msg[i]->msg) - 1] != '\n')
                    fputc('\n', stdout);
                break;
            default:
                // TODO Log Error out... we should never reach this code
                if(aresp[i].resp == NULL) {
                    free_resp(i, aresp);
                    *resp = NULL;
                    return (PAM_CONV_ERR);
                }
        }
    }

    return (PAM_SUCCESS);
}
#endif

static UA_StatusCode
activateSession_default(UA_Server *server, UA_AccessControl *ac,
                        const UA_EndpointDescription *endpointDescription,
                        const UA_ByteString *secureChannelRemoteCertificate,
                        const UA_NodeId *sessionId,
                        const UA_ExtensionObject *userIdentityToken,
                        void **sessionContext) {
    AccessControlContext *context = (AccessControlContext *)ac->context;

    /* The empty token is interpreted as anonymous */
    if(userIdentityToken->encoding == UA_EXTENSIONOBJECT_ENCODED_NOBODY) {
        if(!context->allowAnonymous)
            return UA_STATUSCODE_BADIDENTITYTOKENINVALID;

        /* No userdata atm */
        *sessionContext = NULL;
        return UA_STATUSCODE_GOOD;
    }

    /* Could the token be decoded? */
    if(userIdentityToken->encoding < UA_EXTENSIONOBJECT_DECODED)
        return UA_STATUSCODE_BADIDENTITYTOKENINVALID;

    /* Anonymous login */
    if(userIdentityToken->content.decoded.type ==
       &UA_TYPES[UA_TYPES_ANONYMOUSIDENTITYTOKEN]) {
        if(!context->allowAnonymous)
            return UA_STATUSCODE_BADIDENTITYTOKENINVALID;

        const UA_AnonymousIdentityToken *token =
            (UA_AnonymousIdentityToken *)userIdentityToken->content.decoded.data;

        /* Compatibility notice: Siemens OPC Scout v10 provides an empty
         * policyId. This is not compliant. For compatibility, assume that empty
         * policyId == ANONYMOUS_POLICY */
        if(token->policyId.data && !UA_String_equal(&token->policyId, &anonymous_policy))
            return UA_STATUSCODE_BADIDENTITYTOKENINVALID;

        /* No userdata atm */
        *sessionContext = NULL;
        return UA_STATUSCODE_GOOD;
    }

    /* Username and password */
    if(userIdentityToken->content.decoded.type ==
       &UA_TYPES[UA_TYPES_USERNAMEIDENTITYTOKEN]) {
        const UA_UserNameIdentityToken *userToken =
            (UA_UserNameIdentityToken *)userIdentityToken->content.decoded.data;

        if(!UA_String_equal(&userToken->policyId, &username_policy))
            return UA_STATUSCODE_BADIDENTITYTOKENINVALID;

        /* The userToken has been decrypted by the server before forwarding
         * it to the plugin. This information can be used here. */
        /* if(userToken->encryptionAlgorithm.length > 0) {} */

        /* Empty username and password */
        if(userToken->userName.length == 0 && userToken->password.length == 0)
            return UA_STATUSCODE_BADIDENTITYTOKENINVALID;

        /* Try to match username/pw */
        UA_Boolean match = false;

#ifdef UA_ENABLE_PAM
        int retval;
        pam_handle_t *pamh = NULL;
        printf("pam_start\n");
        /* init the password string and add one char for the string terminator (/n) */
        char pw[userToken->password.length + 1];
        memset(pw, '\0', sizeof(pw));
        strncpy(pw, (const char *)userToken->password.data, userToken->password.length);

        struct pam_conv conversation = {convCallback, pw};

        retval = pam_start("opcua", (const char *)userToken->userName.data, &conversation,
                           &pamh);

        if(retval == PAM_SUCCESS) {
            retval = pam_authenticate(pamh, 0); /* is user really user? */
        }

        if(retval == PAM_SUCCESS) {
            retval = pam_acct_mgmt(pamh, 0); /* permitted access? */
        }

        if(pam_end(pamh, retval) != PAM_SUCCESS) { /* close Linux-PAM */
            pamh = NULL;
        }

        if(retval == PAM_SUCCESS) {
            match = true;
        }
#else
        for(size_t i = 0; i < context->usernamePasswordLoginSize; i++) {
            if(UA_String_equal(&userToken->userName,
                               &context->usernamePasswordLogin[i].username) &&
               UA_String_equal(&userToken->password,
                               &context->usernamePasswordLogin[i].password)) {
                match = true;
                break;
            }
        }
#endif
        if(!match)
            return UA_STATUSCODE_BADUSERACCESSDENIED;

        /* No userdata atm */
        *sessionContext = NULL;
        return UA_STATUSCODE_GOOD;
    }

    /* Unsupported token type */
    return UA_STATUSCODE_BADIDENTITYTOKENINVALID;
}

static void
closeSession_default(UA_Server *server, UA_AccessControl *ac, const UA_NodeId *sessionId,
                     void *sessionContext) {
    /* no context to clean up */
}

static UA_UInt32
getUserRightsMask_default(UA_Server *server, UA_AccessControl *ac,
                          const UA_NodeId *sessionId, void *sessionContext,
                          const UA_NodeId *nodeId, void *nodeContext) {
    return 0xFFFFFFFF;
}

static UA_Byte
getUserAccessLevel_default(UA_Server *server, UA_AccessControl *ac,
                           const UA_NodeId *sessionId, void *sessionContext,
                           const UA_NodeId *nodeId, void *nodeContext) {
    return 0xFF;
}

static UA_Boolean
getUserExecutable_default(UA_Server *server, UA_AccessControl *ac,
                          const UA_NodeId *sessionId, void *sessionContext,
                          const UA_NodeId *methodId, void *methodContext) {
    return true;
}

static UA_Boolean
getUserExecutableOnObject_default(UA_Server *server, UA_AccessControl *ac,
                                  const UA_NodeId *sessionId, void *sessionContext,
                                  const UA_NodeId *methodId, void *methodContext,
                                  const UA_NodeId *objectId, void *objectContext) {
    return true;
}

static UA_Boolean
allowAddNode_default(UA_Server *server, UA_AccessControl *ac, const UA_NodeId *sessionId,
                     void *sessionContext, const UA_AddNodesItem *item) {
    return true;
}

static UA_Boolean
allowAddReference_default(UA_Server *server, UA_AccessControl *ac,
                          const UA_NodeId *sessionId, void *sessionContext,
                          const UA_AddReferencesItem *item) {
    return true;
}

static UA_Boolean
allowDeleteNode_default(UA_Server *server, UA_AccessControl *ac,
                        const UA_NodeId *sessionId, void *sessionContext,
                        const UA_DeleteNodesItem *item) {
    return true;
}

static UA_Boolean
allowDeleteReference_default(UA_Server *server, UA_AccessControl *ac,
                             const UA_NodeId *sessionId, void *sessionContext,
                             const UA_DeleteReferencesItem *item) {
    return true;
}

static UA_Boolean
allowBrowseNode_default(UA_Server *server, UA_AccessControl *ac,
                        const UA_NodeId *sessionId, void *sessionContext,
                        const UA_NodeId *nodeId, void *nodeContext) {
    return true;
}

#ifdef UA_ENABLE_HISTORIZING
static UA_Boolean
allowHistoryUpdateUpdateData_default(UA_Server *server, UA_AccessControl *ac,
                                     const UA_NodeId *sessionId, void *sessionContext,
                                     const UA_NodeId *nodeId,
                                     UA_PerformUpdateType performInsertReplace,
                                     const UA_DataValue *value) {
    return true;
}

static UA_Boolean
allowHistoryUpdateDeleteRawModified_default(UA_Server *server, UA_AccessControl *ac,
                                            const UA_NodeId *sessionId,
                                            void *sessionContext, const UA_NodeId *nodeId,
                                            UA_DateTime startTimestamp,
                                            UA_DateTime endTimestamp,
                                            bool isDeleteModified) {
    return true;
}
#endif

/***************************************/
/* Create Delete Access Control Plugin */
/***************************************/

static void
clear_default(UA_AccessControl *ac) {
    UA_Array_delete((void *)(uintptr_t)ac->userTokenPolicies, ac->userTokenPoliciesSize,
                    &UA_TYPES[UA_TYPES_USERTOKENPOLICY]);
    ac->userTokenPolicies = NULL;
    ac->userTokenPoliciesSize = 0;

    AccessControlContext *context = (AccessControlContext *)ac->context;

    if(context) {
        for(size_t i = 0; i < context->usernamePasswordLoginSize; i++) {
            UA_String_deleteMembers(&context->usernamePasswordLogin[i].username);
            UA_String_deleteMembers(&context->usernamePasswordLogin[i].password);
        }
        if(context->usernamePasswordLoginSize > 0)
            UA_free(context->usernamePasswordLogin);
        UA_free(ac->context);
        ac->context = NULL;
    }
}

UA_StatusCode
UA_AccessControl_default(UA_ServerConfig *config, UA_Boolean allowAnonymous,
                         const UA_ByteString *userTokenPolicyUri,
                         size_t usernamePasswordLoginSize,
                         const UA_UsernamePasswordLogin *usernamePasswordLogin) {
    UA_AccessControl *ac = &config->accessControl;
    ac->clear = clear_default;
    ac->activateSession = activateSession_default;
    ac->closeSession = closeSession_default;
    ac->getUserRightsMask = getUserRightsMask_default;
    ac->getUserAccessLevel = getUserAccessLevel_default;
    ac->getUserExecutable = getUserExecutable_default;
    ac->getUserExecutableOnObject = getUserExecutableOnObject_default;
    ac->allowAddNode = allowAddNode_default;
    ac->allowAddReference = allowAddReference_default;
    ac->allowBrowseNode = allowBrowseNode_default;

#ifdef UA_ENABLE_HISTORIZING
    ac->allowHistoryUpdateUpdateData = allowHistoryUpdateUpdateData_default;
    ac->allowHistoryUpdateDeleteRawModified = allowHistoryUpdateDeleteRawModified_default;
#endif

    ac->allowDeleteNode = allowDeleteNode_default;
    ac->allowDeleteReference = allowDeleteReference_default;

    AccessControlContext *context =
        (AccessControlContext *)UA_malloc(sizeof(AccessControlContext));
    if(!context)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    memset(context, 0, sizeof(AccessControlContext));
    ac->context = context;

    /* Allow anonymous? */
    context->allowAnonymous = allowAnonymous;

#ifndef UA_ENABLE_PAM
    /* Copy username/password to the access control plugin */
    if(usernamePasswordLoginSize > 0) {
        context->usernamePasswordLogin = (UA_UsernamePasswordLogin *)UA_malloc(
            usernamePasswordLoginSize * sizeof(UA_UsernamePasswordLogin));
        if(!context->usernamePasswordLogin)
            return UA_STATUSCODE_BADOUTOFMEMORY;
        context->usernamePasswordLoginSize = usernamePasswordLoginSize;
        for(size_t i = 0; i < usernamePasswordLoginSize; i++) {
            UA_String_copy(&usernamePasswordLogin[i].username,
                           &context->usernamePasswordLogin[i].username);
            UA_String_copy(&usernamePasswordLogin[i].password,
                           &context->usernamePasswordLogin[i].password);
        }
    }
#endif

    /* Set the allowed policies */
    size_t policies = 0;
    if(allowAnonymous)
        policies++;

#ifdef UA_ENABLE_PAM
    policies++;
#else
    /* Set the allowed policies */
    if(usernamePasswordLoginSize > 0)
        policies++;
#endif

    ac->userTokenPoliciesSize = 0;
    ac->userTokenPolicies =
        (UA_UserTokenPolicy *)UA_Array_new(policies, &UA_TYPES[UA_TYPES_USERTOKENPOLICY]);
    if(!ac->userTokenPolicies)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    ac->userTokenPoliciesSize = policies;

    policies = 0;
    if(allowAnonymous) {
        ac->userTokenPolicies[policies].tokenType = UA_USERTOKENTYPE_ANONYMOUS;
        ac->userTokenPolicies[policies].policyId = UA_STRING_ALLOC(ANONYMOUS_POLICY);
        if(!ac->userTokenPolicies[policies].policyId.data)
            return UA_STATUSCODE_BADOUTOFMEMORY;
        policies++;
    }

#ifndef UA_ENABLE_PAM
    if(usernamePasswordLoginSize > 0) {
#endif
        ac->userTokenPolicies[policies].tokenType = UA_USERTOKENTYPE_USERNAME;
        ac->userTokenPolicies[policies].policyId = UA_STRING_ALLOC(USERNAME_POLICY);
        if(!ac->userTokenPolicies[policies].policyId.data)
            return UA_STATUSCODE_BADOUTOFMEMORY;

#if UA_LOGLEVEL <= 400
        const UA_String noneUri =
            UA_STRING("http://opcfoundation.org/UA/SecurityPolicy#None");
        if(UA_ByteString_equal(userTokenPolicyUri, &noneUri)) {
            UA_LOG_WARNING(&config->logger, UA_LOGCATEGORY_SERVER,
                           "Username/Password access control configured, but no "
                           "encrypting SecurityPolicy. "
                           "This can leak credentials on the network.");
        }
#endif
        return UA_ByteString_copy(userTokenPolicyUri,
                                  &ac->userTokenPolicies[policies].securityPolicyUri);
#ifndef UA_ENABLE_PAM
    }
#endif
    return UA_STATUSCODE_GOOD;
}
