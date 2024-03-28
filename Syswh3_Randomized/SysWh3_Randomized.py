import argparse
import os
import sys
import random
import string
list_of_SysWh = ['JUMPER',
                 'internal_cleancall_wow64_gate',
                 'local_is_wow64',
                 'SW3_SYSCALL_LIST',
                 'SW3_SyscallList',
                 'SearchAndReplace',
                 'SW3_HashSyscall',
                 'SW3_SEED',
                 'PartialName',
                 'SC_Address',
                 'NtApiAddress',
                 'searchLimit',
                 'syscall_code',
                 'distance_to_syscall',
                 'DEBUG',
                 'num_jumps',
                 'SW3_PopulateSyscallList',
                 'PSW3_PEB_LDR_DATA',
                 'Peb',
                 'ExportDirectory',
                 'PSW3_LDR_DATA_TABLE_ENTRY',
                 'LdrEntry',
                 'DosHeader',
                 'NtHeaders',
                 'DllName',
                 'Entries',
                 'SW3_MAX_ENTRIES',
                 'TempEntry',
                 'SW3_GetSyscallNumber',
                 'SW3_GetSyscallAddress',
                 'SW3_GetRandomSyscallAddress',
                 'index',
                 'SW3_HEADER_H_',
                 '_NTDEF_',
                 'PNTSTATUS',
                 'NTSTATUS',
                 'SW3_SEED',
                 'SW3_ROL8',
                 'SW3_ROR8',
                 'SW3_ROX8',
                 'SW3_RVA2VA',
                 'Type',
                 'DllBase',
                 'Rva',
                 'PSW3_SYSCALL_ENTRY',
                 '_SW3_SYSCALL_ENTRY',
                 'SW3_SYSCALL_ENTRY',
                 'PSW3_SYSCALL_LIST',
                 '_SW3_SYSCALL_LIST',
                 'SW3_SYSCALL_LIST',
                 'Count',
                 'Entries',
                 'PSW3_PEB_LDR_DATA',
                 '_SW3_PEB_LDR_DATA',
                 'SW3_PEB_LDR_DATA',
                 'PSW3_LDR_DATA_TABLE_ENTRY',
                 '_SW3_LDR_DATA_TABLE_ENTRY',
                 'SW3_LDR_DATA_TABLE_ENTRY',
                 'PSW3_PEB',
                 '_SW3_PEB',
                 'SW3_PEB',
                 'FunctionName',
                 'SyscallAddress',
                 'FunctionHash',
                 'Hash',
                 'Reserved2',
                 'Reserved1',
                 'Reserved3',
                 'InMemoryOrderModuleList',
                 'InMemoryOrderLinks',
                 'BeingDebugged',
                 'SEARCH_AND_REPLACE'
                 ]
list_of_APIs = ['NtAccessCheck',
                'NtYieldExecution',
                'NtWriteVirtualMemory',
                'NtWriteRequestData',
                'NtWriteFileGather',
                'NtWriteFile',
                'NtWorkerFactoryWorkerReady',
                'NtWaitLowEventPair',
                'NtWaitHighEventPair',
                'NtWaitForWorkViaWorkerFactory',
                'NtWaitForWnfNotifications',
                'NtWaitForSingleObject',
                'NtWaitForMultipleObjects32',
                'NtWaitForMultipleObjects',
                'NtWaitForKeyedEvent',
                'NtWaitForDebugEvent',
                'NtWaitForAlertByThreadId',
                'NtVdmControl',
                'NtUpdateWnfStateData',
                'NtUnsubscribeWnfStateChange',
                'NtUnmapViewOfSectionEx',
                'NtUnmapViewOfSection',
                'NtUnlockVirtualMemory',
                'NtUnlockFile',
                'NtUnloadKeyEx',
                'NtUnloadKey2',
                'NtUnloadKey',
                'NtUnloadDriver',
                'NtUmsThreadYield',
                'NtTranslateFilePath',
                'NtTraceEvent',
                'NtTraceControl',
                'NtThawTransactions',
                'NtThawRegistry',
                'NtTestAlert',
                'NtTerminateThread',
                'NtTerminateProcess',
                'NtTerminateJobObject',
                'NtTerminateEnclave',
                'NtSystemDebugControl',
                'NtSuspendThread',
                'NtSuspendProcess',
                'NtSubscribeWnfStateChange',
                'NtStopProfile',
                'NtStartTm',
                'NtStartProfile',
                'NtSinglePhaseReject',
                'NtSignalAndWaitForSingleObject',
                'NtShutdownWorkerFactory',
                'NtShutdownSystem',
                'NtSetWnfProcessNotificationEvent',
                'NtSetVolumeInformationFile',
                'NtSetValueKey',
                'NtSetUuidSeed',
                'NtSetTimerResolution',
                'NtSetTimerEx',
                'NtSetTimer2',
                'NtSetTimer',
                'NtSetThreadExecutionState',
                'NtSetSystemTime',
                'NtSetSystemPowerState',
                'NtSetSystemInformation',
                'NtSetSystemEnvironmentValueEx',
                'NtSetSystemEnvironmentValue',
                'NtSetSecurityObject',
                'NtSetQuotaInformationFile',
                'NtSetLowWaitHighEventPair',
                'NtSetLowEventPair',
                'NtSetLdtEntries',
                'NtSetIRTimer',
                'NtSetIoCompletionEx',
                'NtSetIoCompletion',
                'NtSetIntervalProfile',
                'NtSetInformationWorkerFactory',
                'NtSetInformationVirtualMemory',
                'NtSetInformationTransactionManager',
                'NtSetInformationTransaction',
                'NtSetInformationToken',
                'NtSetInformationThread',
                'NtSetInformationSymbolicLink',
                'NtSetInformationResourceManager',
                'NtSetInformationProcess',
                'NtSetInformationObject',
                'NtSetInformationKey',
                'NtSetInformationJobObject',
                'NtSetInformationFile',
                'NtSetInformationEnlistment',
                'NtSetInformationDebugObject',
                'NtSetHighWaitLowEventPair',
                'NtSetHighEventPair',
                'NtSetEventBoostPriority',
                'NtSetEvent',
                'NtSetEaFile',
                'NtSetDriverEntryOrder',
                'NtSetDefaultUILanguage',
                'NtSetDefaultLocale',
                'NtSetDefaultHardErrorPort',
                'NtSetDebugFilterState',
                'NtSetContextThread',
                'NtSetCachedSigningLevel2',
                'NtSetCachedSigningLevel',
                'NtSetBootOptions',
                'NtSetBootEntryOrder',
                'NtSerializeBoot',
                'NtSecureConnectPort',
                'NtSavepointTransaction',
                'NtSavepointComplete',
                'NtSaveMergedKeys',
                'NtSaveKeyEx',
                'NtSaveKey',
                'NtRollforwardTransactionManager',
                'NtRollbackTransaction',
                'NtRollbackSavepointTransaction',
                'NtRollbackRegistryTransaction',
                'NtRollbackEnlistment',
                'NtRollbackComplete',
                'NtRevertContainerImpersonation',
                'NtResumeThread',
                'NtResumeProcess',
                'NtRestoreKey',
                'NtResetWriteWatch',
                'NtResetEvent',
                'NtRequestWakeupLatency',
                'NtRequestWaitReplyPort',
                'NtRequestPort',
                'NtRequestDeviceWakeup',
                'NtReplyWaitReplyPort',
                'NtReplyWaitReceivePortEx',
                'NtReplyWaitReceivePort',
                'NtReplyPort',
                'NtReplacePartitionUnit',
                'NtReplaceKey',
                'NtRenameTransactionManager',
                'NtRenameKey',
                'NtRemoveProcessDebug',
                'NtRemoveIoCompletionEx',
                'NtRemoveIoCompletion',
                'NtReleaseWorkerFactoryWorker',
                'NtReleaseSemaphore',
                'NtReleaseMutant',
                'NtReleaseKeyedEvent',
                'NtReleaseCMFViewOwnership',
                'NtRegisterThreadTerminatePort',
                'NtRegisterProtocolAddressInformation',
                'NtRecoverTransactionManager',
                'NtRecoverResourceManager',
                'NtRecoverEnlistment',
                'NtReadVirtualMemory',
                'NtReadRequestData',
                'NtReadOnlyEnlistment',
                'NtReadFileScatter',
                'NtReadFile',
                'NtRaiseHardError',
                'NtRaiseException',
                'NtQueueApcThreadEx',
                'NtQueueApcThread',
                'NtQueryWnfStateNameInformation',
                'NtQueryWnfStateData',
                'NtQueryVolumeInformationFile',
                'NtQueryVirtualMemory',
                'NtQueryValueKey',
                'NtQueryTimerResolution',
                'NtQueryTimer',
                'NtQuerySystemTime',
                'NtQuerySystemInformationEx',
                'NtQuerySystemInformation',
                'NtQuerySystemEnvironmentValueEx',
                'NtQuerySystemEnvironmentValue',
                'NtQuerySymbolicLinkObject',
                'NtQuerySemaphore',
                'NtQuerySecurityPolicy',
                'NtQuerySecurityObject',
                'NtQuerySecurityAttributesToken',
                'NtQuerySection',
                'NtQueryQuotaInformationFile',
                'NtQueryPortInformationProcess',
                'NtQueryPerformanceCounter',
                'NtQueryOpenSubKeysEx',
                'NtQueryOpenSubKeys',
                'NtQueryObject',
                'NtQueryMutant',
                'NtQueryMultipleValueKey',
                'NtQueryLicenseValue',
                'NtQueryKey',
                'NtQueryIoCompletion',
                'NtQueryIntervalProfile',
                'NtQueryInstallUILanguage',
                'NtQueryInformationWorkerFactory',
                'NtQueryInformationTransactionManager',
                'NtQueryInformationTransaction',
                'NtQueryInformationToken',
                'NtQueryInformationThread',
                'NtQueryInformationResourceManager',
                'NtQueryInformationProcess',
                'NtQueryInformationPort',
                'NtQueryInformationJobObject',
                'NtQueryInformationFile',
                'NtQueryInformationEnlistment',
                'NtQueryInformationByName',
                'NtQueryInformationAtom',
                'NtQueryFullAttributesFile',
                'NtQueryEvent',
                'NtQueryEaFile',
                'NtQueryDriverEntryOrder',
                'NtQueryDirectoryObject',
                'NtQueryDirectoryFileEx',
                'NtQueryDirectoryFile',
                'NtQueryDefaultUILanguage',
                'NtQueryDefaultLocale',
                'NtQueryDebugFilterState',
                'NtQueryBootOptions',
                'NtQueryBootEntryOrder',
                'NtQueryAuxiliaryCounterFrequency',
                'NtQueryAttributesFile',
                'NtPulseEvent',
                'NtPullTransaction',
                'NtProtectVirtualMemory',
                'NtPropagationFailed',
                'NtPropagationComplete',
                'NtPrivilegeObjectAuditAlarm',
                'NtPrivilegedServiceAuditAlarm',
                'NtPrivilegeCheck',
                'NtPrePrepareEnlistment',
                'NtPrePrepareComplete',
                'NtPrepareEnlistment',
                'NtPrepareComplete',
                'NtPowerInformation',
                'NtPlugPlayControl',
                'NtOpenTransactionManager',
                'NtOpenTransaction',
                'NtOpenTimer',
                'NtOpenThreadTokenEx',
                'NtOpenThreadToken',
                'NtOpenThread',
                'NtOpenSymbolicLinkObject',
                'NtOpenSession',
                'NtOpenSemaphore',
                'NtOpenSection',
                'NtOpenResourceManager',
                'NtOpenRegistryTransaction',
                'NtOpenProcessTokenEx',
                'NtOpenProcessToken',
                'NtOpenProcess',
                'NtOpenPrivateNamespace',
                'NtOpenPartition',
                'NtOpenObjectAuditAlarm',
                'NtOpenMutant',
                'NtOpenKeyTransactedEx',
                'NtOpenKeyTransacted',
                'NtOpenKeyEx',
                'NtOpenKeyedEvent',
                'NtOpenKey',
                'NtOpenJobObject',
                'NtOpenIoCompletion',
                'NtOpenFile',
                'NtOpenEventPair',
                'NtOpenEvent',
                'NtOpenEnlistment',
                'NtOpenDirectoryObject',
                'NtNotifyChangeSession',
                'NtNotifyChangeMultipleKeys',
                'NtNotifyChangeKey',
                'NtNotifyChangeDirectoryFileEx',
                'NtNotifyChangeDirectoryFile',
                'NtModifyDriverEntry',
                'NtModifyBootEntry',
                'NtMarshallTransaction',
                'NtMapViewOfSectionEx',
                'NtMapViewOfSection',
                'NtMapUserPhysicalPagesScatter',
                'NtMapUserPhysicalPages',
                'NtMapCMFModule',
                'NtManagePartition',
                'NtManageHotPatch',
                'NtMakeTemporaryObject',
                'NtMakePermanentObject',
                'NtLockVirtualMemory',
                'NtLockRegistryKey',
                'NtLockProductActivationKeys',
                'NtLockFile',
                'NtLoadKeyEx',
                'NtLoadKey2',
                'NtLoadKey',
                'NtLoadHotPatch',
                'NtLoadEnclaveData',
                'NtLoadDriver',
                'NtListTransactions',
                'NtListenPort',
                'NtIsUILanguageComitted',
                'NtIsSystemResumeAutomatic',
                'NtIsProcessInJob',
                'NtInitiatePowerAction',
                'NtInitializeRegistry',
                'NtInitializeNlsFiles',
                'NtInitializeEnclave',
                'NtImpersonateThread',
                'NtImpersonateClientOfPort',
                'NtImpersonateAnonymousToken',
                'NtGetWriteWatch',
                'NtGetPlugPlayEvent',
                'NtGetNotificationResourceManager',
                'NtGetNlsSectionPtr',
                'NtGetNextThread',
                'NtGetNextProcess',
                'NtGetMUIRegistryInfo',
                'NtGetDevicePowerState',
                'NtGetCurrentProcessorNumberEx',
                'NtGetCurrentProcessorNumber',
                'NtGetContextThread',
                'NtGetCompleteWnfStateSubscription',
                'NtGetCachedSigningLevel',
                'NtFsControlFile',
                'NtFreezeTransactions',
                'NtFreezeRegistry',
                'NtFreeVirtualMemory',
                'NtFreeUserPhysicalPages',
                'NtFlushWriteBuffer',
                'NtFlushVirtualMemory',
                'NtFlushProcessWriteBuffers',
                'NtFlushKey',
                'NtFlushInstructionCache',
                'NtFlushInstallUILanguage',
                'NtFlushBuffersFileEx',
                'NtFlushBuffersFile',
                'NtFindAtom',
                'NtFilterTokenEx',
                'NtFilterToken',
                'NtFilterBootOption',
                'NtExtendSection',
                'NtEnumerateValueKey',
                'NtEnumerateTransactionObject',
                'NtEnumerateSystemEnvironmentValuesEx',
                'NtEnumerateKey',
                'NtEnumerateDriverEntries',
                'NtEnumerateBootEntries',
                'NtEnableLastKnownGood',
                'NtDuplicateToken',
                'NtDuplicateObject',
                'NtDrawText',
                'NtDisplayString',
                'NtDisableLastKnownGood',
                'NtDeviceIoControlFile',
                'NtDeleteWnfStateName',
                'NtDeleteWnfStateData',
                'NtDeleteValueKey',
                'NtDeletePrivateNamespace',
                'NtDeleteObjectAuditAlarm',
                'NtDeleteKey',
                'NtDeleteFile',
                'NtDeleteDriverEntry',
                'NtDeleteBootEntry',
                'NtDeleteAtom',
                'NtDelayExecution',
                'NtDebugContinue',
                'NtDebugActiveProcess',
                'NtCreateWorkerFactory',
                'NtCreateWnfStateName',
                'NtCreateWaitCompletionPacket',
                'NtCreateWaitablePort',
                'NtCreateUserProcess',
                'NtCreateTransactionManager',
                'NtCreateTransaction',
                'NtCreateTokenEx',
                'NtCreateToken',
                'NtCreateTimer2',
                'NtCreateTimer',
                'NtCreateThreadEx',
                'NtCreateThread',
                'NtCreateSymbolicLinkObject',
                'NtCreateSemaphore',
                'NtCreateSectionEx',
                'NtCreateSection',
                'NtCreateResourceManager',
                'NtCreateRegistryTransaction',
                'NtCreateProfileEx',
                'NtCreateProfile',
                'NtCreateProcessEx',
                'NtCreateProcess',
                'NtCreatePrivateNamespace',
                'NtCreatePort',
                'NtCreatePartition',
                'NtCreatePagingFile',
                'NtCreateNamedPipeFile',
                'NtCreateMutant',
                'NtCreateMailslotFile',
                'NtCreateLowBoxToken',
                'NtCreateKeyTransacted',
                'NtCreateKeyedEvent',
                'NtCreateKey',
                'NtCreateJobSet',
                'NtCreateJobObject',
                'NtCreateIRTimer',
                'NtCreateIoCompletion',
                'NtCreateFile',
                'NtCreateEventPair',
                'NtCreateEvent',
                'NtCreateEnlistment',
                'NtCreateEnclave',
                'NtCreateDirectoryObjectEx',
                'NtCreateDirectoryObject',
                'NtCreateDebugObject',
                'NtCreateCrossVmEvent',
                'NtConvertBetweenAuxiliaryCounterAndPerformanceCounter',
                'NtContinueEx',
                'NtContinue',
                'NtConnectPort',
                'NtCompressKey',
                'NtCompleteConnectPort',
                'NtCompareTokens',
                'NtCompareSigningLevels',
                'NtCompareObjects',
                'NtCompactKeys',
                'NtCommitTransaction',
                'NtCommitRegistryTransaction',
                'NtCommitEnlistment',
                'NtCommitComplete',
                'NtCloseObjectAuditAlarm',
                'NtClose',
                'NtClearSavepointTransaction',
                'NtClearEvent',
                'NtClearAllSavepointsTransaction',
                'NtCancelWaitCompletionPacket',
                'NtCancelTimer2',
                'NtCancelTimer',
                'NtCancelSynchronousIoFile',
                'NtCancelIoFileEx',
                'NtCancelIoFile',
                'NtCancelDeviceWakeupRequest',
                'NtCallEnclave',
                'NtCallbackReturn',
                'NtAssociateWaitCompletionPacket',
                'NtAssignProcessToJobObject',
                'NtAreMappedFilesTheSame',
                'NtApphelpCacheControl',
                'NtAlpcSetInformation',
                'NtAlpcSendWaitReceivePort',
                'NtAlpcRevokeSecurityContext',
                'NtAlpcQueryInformationMessage',
                'NtAlpcQueryInformation',
                'NtAlpcOpenSenderThread',
                'NtAlpcOpenSenderProcess',
                'NtAlpcImpersonateClientOfPort',
                'NtAlpcImpersonateClientContainerOfPort',
                'NtAlpcDisconnectPort',
                'NtAlpcDeleteSecurityContext',
                'NtAlpcDeleteSectionView',
                'NtAlpcDeleteResourceReserve',
                'NtAlpcDeletePortSection',
                'NtAlpcCreateSecurityContext',
                'NtAlpcCreateSectionView',
                'NtAlpcCreateResourceReserve',
                'NtAlpcCreatePortSection',
                'NtAlpcCreatePort',
                'NtAlpcConnectPortEx',
                'NtAlpcConnectPort',
                'NtAlpcCancelMessage',
                'NtAlpcAcceptConnectPort',
                'NtAllocateVirtualMemoryEx',
                'NtAllocateVirtualMemory',
                'NtAllocateUuids',
                'NtAllocateUserPhysicalPages',
                'NtAllocateReserveObject',
                'NtAllocateLocallyUniqueId',
                'NtAlertThreadByThreadId',
                'NtAlertThread',
                'NtAlertResumeThread',
                'NtAdjustTokenClaimsAndDeviceGroups',
                'NtAdjustPrivilegesToken',
                'NtAdjustGroupsToken',
                'NtAddDriverEntry',
                'NtAddBootEntry',
                'NtAddAtomEx',
                'NtAddAtom',
                'NtAcquireProcessActivityReference',
                'NtAcquireCMFViewOwnership',
                'NtAccessCheckByTypeResultListAndAuditAlarmByHandle',
                'NtAccessCheckByTypeResultListAndAuditAlarm',
                'NtAccessCheckByTypeResultList',
                'NtAccessCheckByTypeAndAuditAlarm',
                'NtAccessCheckByType',
                'NtAccessCheckAndAuditAlarm',
                'NtAcceptConnectPort',
                ]
banner = '''___   ___  __       ___       ______   ____    ____  ___         
\  \ /  / |  |     /   \     /  __  \  \   \  /   / /   \     /  __  \  
 \  V  /  |  |    /  ^  \   |  |  |  |  \   \/   / /  ^  \   |  |  |  | 
  >   <   |  |   /  /_\  \  |  |  |  |   \_    _/ /  /_\  \  |  |  |  | 
 /  .  \  |  |  /  _____  \ |  `--'  |     |  |  /  _____  \ |  `--'  | 
/__/ \__\ |__| /__/     \__\ \______/      |__| /__/     \__\ \______/   J

A tool that dynamically modifies syswh3 static features against AV/EDR static detection
                                                    Github:https://github.com/xiaoyaoxianj
'''
api_hash_dict = {}
SysWh_hash_dict = {}
changed_api_list = [""]
modified_strings_set = set()

def genkey(length):
    letters = string.ascii_letters
    key = ""
    for i in range(length):
        z = random.choice(letters)
        key = key + z
    return key

def populate(len):
    for i in list_of_APIs:
        modified_string = "Sw3" + i
        modified_strings_set.add(modified_string)
    for i in modified_strings_set:
        api_hash_dict[i] = genkey(len)
    for i in list_of_SysWh:
        api_hash_dict[i] = genkey(len)

def repalce_code(output_file, input_file):
    output = open(output_file, 'w')
    newline = ""
    syscall_file = open(input_file, 'r').readlines()
    for i in syscall_file:
        for api in modified_strings_set:
            if api in i:
                newline = i.replace(api, api_hash_dict.get(api))
                output.write(newline)
                i = ""
                if api not in changed_api_list:
                    changed_api_list.append(api)
                break
        for api in list_of_SysWh:
            if api in i:
                newline = i.replace(api, api_hash_dict.get(api))
                output.write(newline)
                i = ""
                break
        if i != "":
            output.write(i)
    output.close()

def transform(file1,file2,file3,suffix):
    if file1.__contains__(".h"):
        filename = file1.split(".h")
        output_file1 = filename[0] + suffix +".h"
    elif file1.__contains__(".asm"):
        filename = file1.split(".asm")
        output_file1 = filename[0] + suffix + ".asm"
    elif file1.__contains__(".c"):
        filename = file1.split(".c")
        output_file1 = filename[0] + suffix +".c"
    else:
        output_file1 = file1 + suffix

    if file2.__contains__(".h"):
        filename = file2.split(".h")
        output_file2 = filename[0] + suffix + ".h"
    elif file2.__contains__(".asm"):
        filename = file2.split(".asm")
        output_file2 = filename[0] + suffix + ".asm"
    elif file2.__contains__(".c"):
        filename = file2.split(".c")
        output_file2 = filename[0] + suffix + ".c"
    else:
        output_file2 = file2 + suffix

    if file3.__contains__(".h"):
        filename = file3.split(".h")
        output_file3 = filename[0] + suffix + ".h"
    elif file3.__contains__(".asm"):
        filename = file3.split(".asm")
        output_file3 = filename[0] + suffix + ".asm"
    elif file3.__contains__(".c"):
        filename = file3.split(".c")
        output_file3 = filename[0] + suffix + "c"
    else:
        output_file3 = file3 + suffix

    return output_file1,output_file2,output_file3

def copy_file(source_file, destination_file):
    try:
        with open(source_file, 'rb') as src_file:
            with open(destination_file, 'wb') as dest_file:
                dest_file.write(src_file.read())
    except IOError as e:
        sys.exit()

def replace_enough(file1,file2,file3):
    s1,s2,s3 = transform(file1, file2, file3, '-modify')
    if os.path.exists(s1) or os.path.exists(s2) or os.path.exists(s3):
        if os.path.exists(s1):
            os.remove(s1)
        if os.path.exists(s2):
            os.remove(s2)
        if os.path.exists(s3):
            os.remove(s3)
    tmp4, tmp5, tmp6 = transform(file1, file2, file3, '-tmp1')
    repalce_code(s1, file1)
    repalce_code(s2, file2)
    repalce_code(s3, file3)
    for i in range(5):
        repalce_code(tmp4, s1)
        repalce_code(tmp5, s2)
        repalce_code(tmp6, s3)
        copy_file(tmp4,s1)
        copy_file(tmp5,s2)
        copy_file(tmp6,s3)
    os.remove(tmp4)
    os.remove(tmp5)
    os.remove(tmp6)
    print("[+]      Replace successfully!")

def main(file1,file2,file3,length):
    print(banner)
    populate(length)
    replace_enough(file1,file2,file3)
    change_log = open("changed_log.txt", 'w')
    for i in changed_api_list:
        if i:
            logger = i + " : " + api_hash_dict.get(i)+'\n'
            change_log.write(logger)
    print("[+]     The log was generated successfully!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='SysWh2_Radmonized')
    parser.add_argument("file1", help="Syswh3 c file", type=str)
    parser.add_argument("file2", help="Syswh3 asm file", type=str)
    parser.add_argument("file3", help="Syswh3 h file", type=str)
    parser.add_argument('-l',"-length",dest='length',default=5 , help='the Length of the Key ', type=int)

    if len(sys.argv) < 4:
        print(banner)
        parser.print_help()
        sys.exit()

    args = parser.parse_args()
    main(args.file1,args.file2,args.file3,args.length)
