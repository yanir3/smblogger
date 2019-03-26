import logging
import ntpath

from impacket import smbserver, version
from impacket import smb3structs as smb2
from impacket.examples import logger
from impacket.nt_errors import STATUS_SUCCESS


class SMB2Commands(smbserver.SMB2Commands):
    @staticmethod
    def smb2TreeConnect(connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respPacket = smb2.SMB2Packet()
        respPacket['Flags']     = smb2.SMB2_FLAGS_SERVER_TO_REDIR
        respPacket['Status']    = STATUS_SUCCESS
        respPacket['CreditRequestResponse'] = 1
        respPacket['Command']   = recvPacket['Command']
        respPacket['SessionID'] = connData['Uid']
        respPacket['Reserved']  = recvPacket['Reserved']
        respPacket['MessageID'] = recvPacket['MessageID']
        respPacket['TreeID']    = recvPacket['TreeID']

        respSMBCommand        = smb2.SMB2TreeConnect_Response()

        treeConnectRequest = smb2.SMB2TreeConnect(recvPacket['Data'])

        errorCode = STATUS_SUCCESS

        ## Process here the request, does the share exist?
        path = str(recvPacket)[treeConnectRequest['PathOffset']:][:treeConnectRequest['PathLength']]
        UNCOrShare = path.decode('utf-16le')

        # Is this a UNC?
        if ntpath.ismount(UNCOrShare):
            path = UNCOrShare.split('\\')[3]
        else:
            path = ntpath.basename(UNCOrShare)

        smbServer.log("SMB2_TREE_CONNECT %s" % path, logging.ERROR)
       
        # Simple way to generate a Tid
        if len(connData['ConnectedShares']) == 0:
           tid = 1
        else:
           tid = connData['ConnectedShares'].keys()[-1] + 1
        connData['ConnectedShares'][tid] = {"yes": "no"}
        connData['ConnectedShares'][tid]['shareName'] = path
        respPacket['TreeID']    = tid
        smbServer.log("Connecting Share(%d:%s)" % (tid,path))
        ##

        if path.upper() == 'IPC$':
            respSMBCommand['ShareType'] = smb2.SMB2_SHARE_TYPE_PIPE
            respSMBCommand['ShareFlags'] = 0x30
        else:
            respSMBCommand['ShareType'] = smb2.SMB2_SHARE_TYPE_DISK
            respSMBCommand['ShareFlags'] = 0x0

        respSMBCommand['Capabilities'] = 0
        respSMBCommand['MaximalAccess'] = 0x000f01ff

        respPacket['Data'] = respSMBCommand

        # Sign the packet if needed
        if connData['SignatureEnabled']:
            smbServer.signSMBv2(respPacket, connData['SigningSessionKey'])
        smbServer.setConnectionData(connId, connData)

        return None, [respPacket], errorCode

smbserver.SMB2Commands = SMB2Commands

def main():
    logger.init()
    logging.getLogger().setLevel(logging.DEBUG)

    server = smbserver.SimpleSMBServer(listenAddress="0.0.0.0", listenPort=445)
    server.setSMB2Support(True)
    server.setSMBChallenge('')

    print "Starting server:"
    server.start()

if __name__ == '__main__':
	main()