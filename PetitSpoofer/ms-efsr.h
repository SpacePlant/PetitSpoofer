

/* this ALWAYS GENERATED file contains the definitions for the interfaces */

// ms-efsr_32
/* File created by MIDL compiler version 8.01.0622 */
/* at Tue Jan 19 04:14:07 2038
 */
 /* Compiler settings for ms-efsr.idl:
     Oicf, W1, Zp8, env=Win32 (32b run), target_arch=X86 8.01.0622
     protocol : dce , ms_ext, c_ext, robust
     error checks: allocation ref bounds_check enum stub_data
     VC __declspec() decoration level:
          __declspec(uuid()), __declspec(selectany), __declspec(novtable)
          DECLSPEC_UUID(), MIDL_INTERFACE()
 */
 /* @@MIDL_FILE_HEADING(  ) */

// ms-efsr_64
/* File created by MIDL compiler version 8.01.0622 */
/* at Tue Jan 19 04:14:07 2038
 */
/* Compiler settings for ms-efsr.idl:
    Oicf, W1, Zp8, env=Win64 (32b run), target_arch=AMD64 8.01.0622 
    protocol : all , ms_ext, c_ext, robust
    error checks: allocation ref bounds_check enum stub_data 
    VC __declspec() decoration level: 
         __declspec(uuid()), __declspec(selectany), __declspec(novtable)
         DECLSPEC_UUID(), MIDL_INTERFACE()
*/
/* @@MIDL_FILE_HEADING(  ) */

/* verify that the <rpcndr.h> version is high enough to compile this file*/
#ifndef __REQUIRED_RPCNDR_H_VERSION__
#define __REQUIRED_RPCNDR_H_VERSION__ 500
#endif

#include "rpc.h"
#include "rpcndr.h"

#ifndef __RPCNDR_H_VERSION__
#error this stub requires an updated version of <rpcndr.h>
#endif /* __RPCNDR_H_VERSION__ */


#ifndef __ms2Defsr_h__
#define __ms2Defsr_h__

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

/* Forward Declarations */ 

/* header files for imported files */
// #include "ms-dtyp.h"

#ifdef __cplusplus
extern "C"{
#endif

// Types from "ms-dtyp.h":
// ===
typedef struct _RPC_SID_IDENTIFIER_AUTHORITY
{
    byte Value[6];
} 	RPC_SID_IDENTIFIER_AUTHORITY;

typedef struct _RPC_SID
{
    unsigned char Revision;
    unsigned char SubAuthorityCount;
    RPC_SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
    /* [size_is] */ unsigned long SubAuthority[1];
} 	RPC_SID;
// ===

#ifndef __efsrpc_INTERFACE_DEFINED__
#define __efsrpc_INTERFACE_DEFINED__

/* interface efsrpc */
/* [version][uuid] */ 

typedef /* [context_handle] */ void *PEXIMPORT_CONTEXT_HANDLE;

typedef struct pipe_EFS_EXIM_PIPE
    {
    void (__RPC_USER * pull) (
        char * state,
        unsigned char * buf,
        unsigned long esize,
        unsigned long * ecount );
    void (__RPC_USER * push) (
        char * state,
        unsigned char * buf,
        unsigned long ecount );
    void (__RPC_USER * alloc) (
        char * state,
        unsigned long bsize,
        unsigned char * * buf,
        unsigned long * bcount );
    char * state;
    } 	EFS_EXIM_PIPE;

typedef struct _EFS_RPC_BLOB2
    {
    /* [range] */ DWORD cbData;
    /* [size_is] */ unsigned char *bData;
    } 	EFS_RPC_BLOB2;

typedef struct _EFS_RPC_BLOB2 *PEFS_RPC_BLOB2;

typedef /* [public] */ struct __MIDL_efsrpc_0001
    {
    DWORD EfsVersion;
    } 	EFS_COMPATIBILITY_INFO2;

typedef unsigned int ALG_ID;

typedef struct _EFS_HASH_BLOB2
    {
    /* [range] */ DWORD cbData;
    /* [size_is] */ unsigned char *bData;
    } 	EFS_HASH_BLOB2;

typedef struct _ENCRYPTION_CERTIFICATE_HASH2
    {
    DWORD cbTotalLength;
    RPC_SID *UserSid;
    EFS_HASH_BLOB2 *Hash;
    /* [string] */ wchar_t *lpDisplayInformation;
    } 	ENCRYPTION_CERTIFICATE_HASH2;

typedef struct _ENCRYPTION_CERTIFICATE_HASH_LIST2
    {
    /* [range] */ DWORD nCert_Hash;
    /* [size_is][size_is] */ ENCRYPTION_CERTIFICATE_HASH2 **Users;
    } 	ENCRYPTION_CERTIFICATE_HASH_LIST2;

typedef struct _CERTIFICATE_BLOB2
    {
    DWORD dwCertEncodingType;
    /* [range] */ DWORD cbData;
    /* [size_is] */ unsigned char *bData;
    } 	EFS_CERTIFICATE_BLOB2;

typedef struct _ENCRYPTION_CERTIFICATE2
    {
    DWORD cbTotalLength;
    RPC_SID *UserSid;
    EFS_CERTIFICATE_BLOB2 *CertBlob;
    } 	ENCRYPTION_CERTIFICATE2;

typedef struct _ENCRYPTION_CERTIFICATE_LIST2
    {
    /* [range] */ DWORD nUsers;
    /* [size_is][size_is] */ ENCRYPTION_CERTIFICATE2 **Users;
    } 	ENCRYPTION_CERTIFICATE_LIST2;

typedef struct _ENCRYPTED_FILE_METADATA_SIGNATURE2
    {
    DWORD dwEfsAccessType;
    ENCRYPTION_CERTIFICATE_HASH_LIST2 *CertificatesAdded;
    ENCRYPTION_CERTIFICATE2 *EncryptionCertificate;
    EFS_RPC_BLOB2 *EfsStreamSignature;
    } 	ENCRYPTED_FILE_METADATA_SIGNATURE2;

typedef /* [public] */ struct __MIDL_efsrpc_0002
    {
    DWORD dwVersion;
    unsigned long Entropy;
    ALG_ID Algorithm;
    unsigned long KeyLength;
    } 	EFS_KEY_INFO2;

typedef /* [public] */ struct __MIDL_efsrpc_0003
    {
    DWORD dwDecryptionError;
    DWORD dwHashOffset;
    DWORD cbHash;
    } 	EFS_DECRYPTION_STATUS_INFO2;

typedef /* [public] */ struct __MIDL_efsrpc_0004
    {
    BOOL bHasCurrentKey;
    DWORD dwEncryptionError;
    } 	EFS_ENCRYPTION_STATUS_INFO2;

typedef struct _ENCRYPTION_PROTECTOR2
    {
    DWORD cbTotalLength;
    RPC_SID *UserSid;
    /* [string] */ wchar_t *lpProtectorDescriptor;
    } 	ENCRYPTION_PROTECTOR2;

typedef struct _ENCRYPTION_PROTECTOR2 *PENCRYPTION_PROTECTOR2;

typedef struct _ENCRYPTION_PROTECTOR_LIST2
    {
    DWORD nProtectors;
    /* [size_is] */ PENCRYPTION_PROTECTOR2 *pProtectors;
    } 	ENCRYPTION_PROTECTOR_LIST2;

typedef struct _ENCRYPTION_PROTECTOR_LIST2 *PENCRYPTION_PROTECTOR_LIST2;

long EfsRpcOpenFileRaw( 
    /* [in] */ handle_t binding_h,
    /* [out] */ PEXIMPORT_CONTEXT_HANDLE *hContext,
    /* [string][in] */ wchar_t *FileName,
    /* [in] */ long Flags);

long EfsRpcReadFileRaw( 
    /* [in] */ PEXIMPORT_CONTEXT_HANDLE hContext,
    /* [out] */ EFS_EXIM_PIPE *EfsOutPipe);

long EfsRpcWriteFileRaw( 
    /* [in] */ PEXIMPORT_CONTEXT_HANDLE hContext,
    /* [in] */ EFS_EXIM_PIPE *EfsInPipe);

void EfsRpcCloseRaw( 
    /* [out][in] */ PEXIMPORT_CONTEXT_HANDLE *hContext);

long EfsRpcEncryptFileSrv( 
    /* [in] */ handle_t binding_h,
    /* [string][in] */ wchar_t *FileName);

long EfsRpcDecryptFileSrv( 
    /* [in] */ handle_t binding_h,
    /* [string][in] */ wchar_t *FileName,
    /* [in] */ unsigned long OpenFlag);

DWORD EfsRpcQueryUsersOnFile( 
    /* [in] */ handle_t binding_h,
    /* [string][in] */ wchar_t *FileName,
    /* [out] */ ENCRYPTION_CERTIFICATE_HASH_LIST2 **Users);

DWORD EfsRpcQueryRecoveryAgents( 
    /* [in] */ handle_t binding_h,
    /* [string][in] */ wchar_t *FileName,
    /* [out] */ ENCRYPTION_CERTIFICATE_HASH_LIST2 **RecoveryAgents);

DWORD EfsRpcRemoveUsersFromFile( 
    /* [in] */ handle_t binding_h,
    /* [string][in] */ wchar_t *FileName,
    /* [in] */ ENCRYPTION_CERTIFICATE_HASH_LIST2 *Users);

DWORD EfsRpcAddUsersToFile( 
    /* [in] */ handle_t binding_h,
    /* [string][in] */ wchar_t *FileName,
    /* [in] */ ENCRYPTION_CERTIFICATE_LIST2 *EncryptionCertificates);

void Opnum10NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

DWORD EfsRpcNotSupported( 
    /* [in] */ handle_t binding_h,
    /* [string][in] */ wchar_t *Reserved1,
    /* [string][in] */ wchar_t *Reserved2,
    /* [in] */ DWORD dwReserved1,
    /* [in] */ DWORD dwReserved2,
    /* [unique][in] */ EFS_RPC_BLOB2 *Reserved,
    /* [in] */ BOOL bReserved);

DWORD EfsRpcFileKeyInfo( 
    /* [in] */ handle_t binding_h,
    /* [string][in] */ wchar_t *FileName,
    /* [in] */ DWORD InfoClass,
    /* [out] */ EFS_RPC_BLOB2 **KeyInfo);

DWORD EfsRpcDuplicateEncryptionInfoFile( 
    /* [in] */ handle_t binding_h,
    /* [string][in] */ wchar_t *SrcFileName,
    /* [string][in] */ wchar_t *DestFileName,
    /* [in] */ DWORD dwCreationDisposition,
    /* [in] */ DWORD dwAttributes,
    /* [unique][in] */ EFS_RPC_BLOB2 *RelativeSD,
    /* [in] */ BOOL bInheritHandle);

void Opnum14NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

DWORD EfsRpcAddUsersToFileEx( 
    /* [in] */ handle_t binding_h,
    /* [in] */ DWORD dwFlags,
    /* [unique][in] */ EFS_RPC_BLOB2 *Reserved,
    /* [string][in] */ wchar_t *FileName,
    /* [in] */ ENCRYPTION_CERTIFICATE_LIST2 *EncryptionCertificates);

DWORD EfsRpcFileKeyInfoEx( 
    /* [in] */ handle_t binding_h,
    /* [in] */ DWORD dwFileKeyInfoFlags,
    /* [unique][in] */ EFS_RPC_BLOB2 *Reserved,
    /* [string][in] */ wchar_t *FileName,
    /* [in] */ DWORD InfoClass,
    /* [out] */ EFS_RPC_BLOB2 **KeyInfo);

void Opnum17NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

DWORD EfsRpcGetEncryptedFileMetadata( 
    /* [in] */ handle_t binding_h,
    /* [ref][string][in] */ wchar_t *FileName,
    /* [ref][out] */ EFS_RPC_BLOB2 **EfsStreamBlob);

DWORD EfsRpcSetEncryptedFileMetadata( 
    /* [in] */ handle_t binding_h,
    /* [ref][string][in] */ wchar_t *FileName,
    /* [unique][in] */ EFS_RPC_BLOB2 *OldEfsStreamBlob,
    /* [ref][in] */ EFS_RPC_BLOB2 *NewEfsStreamBlob,
    /* [unique][in] */ ENCRYPTED_FILE_METADATA_SIGNATURE2 *NewEfsSignature);

DWORD EfsRpcFlushEfsCache( 
    /* [in] */ handle_t binding_h);

long EfsRpcEncryptFileExSrv( 
    /* [in] */ handle_t binding_h,
    /* [string][in] */ wchar_t *FileName,
    /* [unique][string][in] */ wchar_t *ProtectorDescriptor,
    /* [in] */ unsigned long Flags);

DWORD EfsRpcQueryProtectors( 
    /* [in] */ handle_t binding_h,
    /* [string][in] */ wchar_t *FileName,
    /* [out] */ PENCRYPTION_PROTECTOR_LIST2 **ppProtectorList);

void Opnum23NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum24NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum25NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum26NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum27NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum28NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum29NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum30NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum31NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum32NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum33NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum34NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum35NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum36NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum37NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum38NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum39NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum40NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum41NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum42NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum43NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum44NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);



extern RPC_IF_HANDLE efsrpc_v1_0_c_ifspec;
extern RPC_IF_HANDLE efsrpc_v1_0_s_ifspec;
#endif /* __efsrpc_INTERFACE_DEFINED__ */

/* Additional Prototypes for ALL interfaces */

void __RPC_USER PEXIMPORT_CONTEXT_HANDLE_rundown( PEXIMPORT_CONTEXT_HANDLE );

/* end of Additional Prototypes */

#ifdef __cplusplus
}
#endif

#endif


