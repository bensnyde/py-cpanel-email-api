"""
=====================================================
 Cpanel API2 Email Module Python Library
=====================================================
:Info: See http://docs.cpanel.net/twiki/bin/view/ApiDocs/Api2/ApiEmail for API implementation.
:Author: Benton Snyder introspectr3@gmail.com
:Website: Noumenal Designs <http://www.noumenaldesigns.com>
:Date: $Date: 2013-08-15 23:32:46 -0600 (Thurs, 15 Aug 2013) $
:Revision: $Revision: 0008 $
:Description: Python library for interfacing Cpanel <http://www.cpanel.net> Email functions.
"""
from httplib import HTTPSConnection
from base64 import b64encode

class Cpanel:
        def __init__(self, url, username, password):
                self.url = url
                self.authHeader = {'Authorization':'Basic ' + b64encode(username+':'+password).decode('ascii')}

        def cQuery(self, queryStr):
                """Queries specified WHM server's JSON API with specified query string.

                :param queryStr: HTTP GET formatted query string
                :returns: json formatted string
                """
                conn = HTTPSConnection(self.url, 2087)
                conn.request('GET', '/json-api/'+queryStr, headers=self.authHeader)
                response = conn.getresponse()
                data = response.read()
                conn.close()
                return data

        # Account Functions

        def createAccount(self, username, domain, *args):
                """Creates a hosting account and sets up its associated domain information.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/CreateAccount
                """
                return self.cQuery('createacct?username='+username+'&domain='+domain)

        def changeAccountPassword(self, username, password, update_db_password=True):
                """Changes the password of a domain owner (cPanel) or reseller (WHM) account.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/ChangePassword
                """
                return self.cQuery('passwd?user='+username+'&pass='+password+'&db_pass_update='+update_db_password)

        def limitAccountBandwidth(self, username, bwlimit):
                """Modifies the bandwidth usage (transfer) limit for a specific account.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/LimitBandwidth
                """
                return self.cQuery('limitbw?user='+username+'&bwlimit='+bwlimit)

        def listAccounts(self, *args):
                """Lists all accounts on the server, and also allows you to search for a specific account or set of accounts.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/ListAccounts
                """
                return self.cQuery('lictaccts')

        def modifyAccount(self, username, *args):
                """Modifies settings for an account.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/ModifyAccount
                """
                return self.cQuery('modifyacct?user='+username)

        def changeAccountDiskQuota(self, username, quota):
                """Changes an account's disk space usage quota.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/EditQuota
                """
                return self.cQuery('editquota?user='+username+'&quota='+quota)

        def getAccountSummary(self, username):
                """Displays pertinent information about a specific account.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/ShowAccountInformation
                """
                return self.cQuery('accountsummary?user='+username)

        def suspendAccount(self, username, reason=""):
                """Allow you to prevent a cPanel user from accessing his or her account.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/SuspendAccount
                """
                return self.cQuery('suspendacct?user='+username+'&reason='+reason)

        def listSuspendedAccounts(self):
                """Generates a list of suspended accounts.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/ListSuspended
                """
                return self.cQuery('listsuspended')

        def terminateAccount(self, username, keep_dns=False):
                """Permanently removes a cPanel account.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/TerminateAccount
                """
                return self.cQuery('removeacct?user='+username+'&keepdns='+keep_dns)

        def unsuspendAccount(self, username):
                """Unsuspend a suspended account.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/UnsuspendAcount
                """
                return self.cQuery('unsuspendacct?user='+username)

        def changeAccountPackage(self, username, package):
                """Changes the hosting package associated with a cPanel account.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/ChangePackage
                """
                return self.cQuery('changepackage?user='+username+'&pkg='+package)

        def getDomainUserdata(self, domain):
                """Obtains user data for a specific domain.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/DomainUserData
                """
                return self.cQuery('domainuserdata?domain='+domain)

        def changeDomainIpAddress(self, domain, ip_address):
                """Change the IP address of a website hosted on your server.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/SetSiteIp
                """
                return self.cQuery('setsiteip?domain='+domain+'&ip='+ip_address)

        def changeAccountIpAddress(self, username, ip_address):
                """Change the IP address of a user account hosted on your server.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/SetSiteIp
                """
                return self.cQuery('setsiteip?user='+username+'&ip='+ip_address)

        def restoreAccountBackup(self, username, backup_type="daily", all_services=True, ip=True, mail=True, mysql=True, subs=True):
                """Restore a user's account from a backup file.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/RestoreAccount
                """
                if(backup_type == "daily" || backup_type == "weekly" || backup_type == "monthly"):
                        return self.cQuery('restoreaccount?api.version=1&user='+username+'&type='+backup_type+'&all='+all_services)

        def setAccountDigestAuthentication(self, username, password, enable_digest=True):
                """Enables or disables Digest Authentication for a user account.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/SetDigestAuth
                """
                return self.cQuery('set_digest_auth?user='+username+'&password='+password+'&enabledigest='+enable_digest+'&api.version=1')

        def getAccountDigestAuthentication(self, username):
                """Checks whether a cPanel user has digest authentication enabled.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/HasDigestAuth
                """
                return self.cQuery('has_digest_auth?user='+username)

        def getPrivileges(self):
                """Generates a list of features you are allowed to use in WHM.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/ViewPrivileges
                """
                return self.cQuery('myprivs')

        def restoreAccountBackupQueued(self, username, restore_point, give_ip=False, mysql=True, subdomains=True, mail_config=True):
                """Restore a user's account from a backup file.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/RestoreQueueAdd
                """
                return self.cQuery('restore_queue_add_task?user='+username+'&restore_point='+restore_point
                        +'&give_ip='+give_ip+'&mysql='+mysql+'&subdomains='+subdomains+'&mail_config='+mail_config)

        def activateRestoreQueue(self):
                """Activate the restore queue and start a process to restore all queued accounts.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/RestoreQueueActivate
                """
                return self.cQuery('restore_queue_activate')

        def getRestoreQueueState(self):
                """See if the queue is actively in the restoration process for certain accounts.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/RestoreQueueIsActive
                """
                return self.cQuery('restore_queue_is_active')

        def getRestoreQueuePending(self):
                """Lists all queued accounts to be restored.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/RestoreQueueList
                """
                return self.cQuery('restore_queue_list_pending')

        def getRestoreQueueActive(self):
                """List all accounts currently in the restoration process.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/RestoreQueueListActive
                """
                return self.cQuery('restore_queue_list_active')

        def getRestoreQueueCompleted(self):
                """Lists all completed restorations, successful restores, failed restores, and the restore log.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/RestoreQueueListCompleted
                """
                return self.cQuery('restore_queue_list_completed')

        def clearRestoreQueuePendingTask(self, username):
                """Clears a single pending account from the Restoration Queue.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/RestoreQueueClearPendingTask
                """
                return self.cQuery('restore_queue_clear_pending_task?user='+username)

        def clearRestoreQueuePendingTasks(self):
                """Clears all pending accounts from the restore queue.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/RestoreQueueClearAllPendingTasks
                """
                return self.cQuery('restore_queue_clear_all_pending_tasks')

        def clearRestoreQueueCompletedTask(self, username):
                """Clears a single completed account from the Restoration Queue.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/RestoreQueueClearCompletedTask
                """
                return self.cQuery('restore_queue_clear_completed_task?user='+username)

        def clearRestoreQueueCompletedTasks(self):
                """Clears all successfully completed accounts from the Restoration Queue.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/RestoreQueueClearAllCompletedTasks
                """
                return self.cQuery('restore_queue_clear_all_completed_tasks')

        def clearRestoreQueueFailedTasks(self):
                """Clears all failed tasks from the Restoration Queue.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/RestoreQueueClearAllFailedTasks
                """
                return self.cQuery('restore_queue_clear_all_failed_tasks')

        def clearRestoreQueueAll(self):
                """Clears all open, unresolved, or pending tasks from the Restoration Queue.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/RestoreQueueClearAllTasks
                """
                return self.cQuery('restore_queue_clear_all_tasks')


        def getBackupConfig(self):
                """Retreieves detailed data from your backup destination configuration file.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/BackupConfigGet
                """
                return self.cQuery('backup_config_get')

        def setBackupConfig(self, *args):
                """Saves the data from the backup configuration page and put the data in /var/cpanel/bakcups/config.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/BackupConfigSet
                """
                return self.cQuery('backup_config_set')

        def setBackupConfigAllUsers(self, state=True):
                """Choose which Backup Configuration to use, and enable or disable backups for all users.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/BackupSkipUsersAll
                """
                return self.cQuery('backup_skip_users_all?state='+state)

        def getBackupConfigAllUsers(self):
                """Retrieves the value from the status log file in the backup_skip_users_all api call.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/BackupSkipUsersAllStatus
                """
                return self.cQuery('backup_skip_users_all_status')

        def getBackupListFiles(self):
                """Lists all backup files available on the server.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/BackupSetList
                """
                return self.cQuery('backup_set_list')

        def getBackupListDates(self):
                """Retrieves a list of all dates with a backup file saved.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/BackupDateList
                """
                return self.cQuery('backup_date_list')

        def getBackupsByDate(self, date):
                """Lists all users with a backup file saved on a specific date that you choose.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/BackupUserList
                """
                return self.cQuery('backup_user_list?restore_point='+date)

        def validateBackupDestination(self, destination_id, disable_on_fail=False):
                """Run a validation routine on a specified backup destination.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/BackupdDestinationValidatet
                """
                return self.cQuery('backup_destination_validate?id='+destination_id+'&disableonfail='+disable_on_fail)

        def addBackupDestination(self, backup_type, *args):
                """Create a backup destination and save it to a config file.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/BackupDestinationAdd
                """
                if(backup_type == "FTP" || backup_type == "Local" || backup_type == "SFTP" || backup_type == "WebDav" || backup_type == "Custom"):
                        return self.cQuery('backup_destination_add?type='+backup_type)

        def setBackupDestination(self, destination_id, *args):
                """Modifies the setup and data for a backup destination.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/BackupDestinationSet
                """
                return self.cQuery('backup_destination_set?id='+destination_id)

        def deleteBackupDestination(self, destination_id):
                """Removes the backup destination config file.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/BackupDestinationDelete
                """
                return self.cQuery('backup_destination_delete?id='+destination_id)

        def getBackupDestinationDetails(self, destination_id):
                """Retrieves detailed data for a specific backup destination from the backup destination config file.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/BackupDestinationGet
                """
                return self.cQuery('backup_destination_get?id='+destination_id)

        def listBackupDestionations(self):
                """Lists all backup destinations, including their configuration information.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/BackupDestinationList
                """
                return self.cQuery('backup_destination_list')

        # Package Functions

        def addPackage(self, name, *args):
                """Adds a new hosting package.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/AddPackage
                """
                return self.cQuery('addpkg?name='+name)

        def deletePackage(self, name):
                """Deletes a specific hosting package.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/DeletePackage
                """
                return self.cQuery('killpkg?pkg='+name)

        def editPackage(self, name, *args):
                """Edits all aspects of a specific hosting package.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/EditPackage
                """
                return self.cQuery('editpkg?name='+name)

        def listPackages(self):
                """Lists all hosting packages available for use by the WHM user who is currently logged in.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/ListPackages
                """
                return self.cQuery('listpkgs')

        def listFeatures(self):
                """Retrieves a list of available features.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/XmlGetFeatureList
                """
                return self.cQuery('getfeaturelist')

        # Service Functions

        def restartService(self, service):
                """Restarts a service (daemon) on the server.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/RestartService
                """
                return self.cQuery('restartservice?service='+service)

        def getServiceStatus(self, service):
                """Lists which services (daemons) are installed and enabled on, and monitored by, your server.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/ServiceStatus
                """
                return self.cQuery('servicestatus?service='+service)

        def configureService(self, service, enabled=True, monitored=True):
                """Enable or disable a service, and enable or disable monitoring of that service.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/ConfigureService
                """
                return self.cQuery('configureservice?service='+service+'&enabled='+enabled+'&monitored='+monitored)

        # SSL Functions

        def getSSLDetails(self, domain):
                """Displays the SSL certificate, private key, and CA bundle/intermediate certificate associated with a specified domain.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/FetchSSL
                """
                return self.cQuery('fetchsslinfo?domain='+domain)

        def generateSSL(self, xemail, host, country, state, city, co, cod, email, password):
                """Generates an SSL certificate.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/GenerateSSL
                """
                return self.cQuery('generatessl?xemail='+xemail+'&host='+host+'&country='+country+
                        '&state='+state+'&city='+city+'&co='+co+'&cod='+cod+'&email='+email+'&pass='+password)

        def installSSL(self, username, domain, cert, key, cab, ip):
                """Installs an SSL certificate.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/InstallSSL
                """
                return self.cQuery('installssl?user='+username+'&domain='+domain+'&cert='+cert+'&key='+key+'&cab='+cab+'&ip='+ip)

        def listSSL(self):
                """Lists all domains on the server that have SSL certificates installed.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/ListSSL
                """
                return self.cQuery('listcrts')

        def setPrimaryDomain(self, servername, vtype="std"):
                """Sets the primary domain on an IP address and port (ssl or std).
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/SetPrimaryDomain
                """
                return self.cQuery('set_primary_servername?api.version=1&servername='+servername+'&type='+vtype)

        def checkSNI(self):
                """See if the server supports SNI, which allows for multiple SSL certificates per IP address and port number.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/CheckSNISupport
                """
                return self.cQuery('is_sni_supported?api.version=1')


        def installServiceSSL(self, service, crt, key, cabundle):
                """Install a new certificate on ftp, exim, dovecot, courier, or cpanel.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/InstallServiceSslCertificate
                """
                return self.cQuery('install_service_ssl_certificate?service='+service+'&crt='+crt+'&key='+key+'&cabundle='+cabundle+'&api.version=1')

        def regenerateServiceSSL(self, service):
                """Regenerate a self-signed certificate and assign the certificate to ftp, exim, dovecot, courier, or cpanel.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/ResetServiceSslCerificate
                """
                return self.cQuery('reset_service_ssl_certificate?api.version=1&service='+service)

        def getServiceSSL(self):
                """Retrieves a list of services and their corresponding certificates.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/FetchServiceCertificates
                """
                return self.cQuery('fetch_service_ssl_components')

        # Reseller Functions

        def demoteReseller(self, username):
                """Removes reseller status from an account.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/RemoveResellerPrivileges
                """
                return self.cQuery('unsetupreseller?user='+username)

        def promoteReseller(self, username, make_owner=False):
                """Gives reseller status to an existing account.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/AddResellerPrivileges
                """
                return self.cQuery('setupreseller?user='+username+'&makeowner='+make_owner)

        def createResellerACL(self, acllist, *args):
                """Creates a new reseller ACL list.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/CreateResellerACLList
                """
                return self.cQuery('saveacllist?acllist='+acllist)

        def listResellerACL(self):
                """Lists the saved reseller ACL lists on the server.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/ListCurrentResellerACLLists
                """
                return self.cQuery('listacls')

        def listResellers(self):
                """Lists the usernames of all resellers on the server.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/ListResellerAccounts
                """
                return self.cQuery('listresellers')

        def getResellerDetails(self, reseller):
                """Shows account statistics for a specific reseller's accounts.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/ListResellersAccountsInformation
                """
                return self.cQuery('resellerstats?reseller='+reseller)

        def getResellerIPs(self, username):
                """Retrieves a list of IP Addresses that are available to a specified reseller.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/GetResellerips
                """
                return self.cQuery('getresellerips?user='+username)

        def setResellerACL(self, reseller, *args):
                """Specifies the ACL for a reseller, or modifies specific ACL items for a reseller.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/SetResellersACLList
                """
                return self.cQuery('setacls?reseller='+reseller)

        def deleteReseller(self, reseller, terminate_reseller=True):
                """Terminates a reseller's main account, as well as all accounts owned by the reseller.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/TerminateResellerandAccounts
                """
                verify = '%20all%20the%20accounts%20owned%20by%20the%20reseller%20'+reseller
                return self.cQuery('terminatereseller?reseller='+reseller+'&terminatereseller='+terminate_reseller+'&verify='+verify)

        def allocateResellerIP(self, username, *args):
                """Add IP addresses to a reseller account.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/SetResellerIps
                """
                return self.cQuery('setresellerips?user='+username)

        def setResellerResourceLimits(self, username, *args):
                """Specify the amount of bandwidth and disk space a reseller is able to use.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/SetResellerLimits
                """
                return self.cQuery('setresellerlimits?user='+username)

        def setResellerPackage(self, username, *args):
                """Control which packages resellers are able to use.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/SetResellerPkgLimit
                """
                return self.cQuery('setresellerpackagelimit?user='+username)

        def setResellerMainIP(self, username, ip):
                """Assigns a main, shared IP address to a reseller.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/SetResellerMainIp
                """
                return self.cQuery('setresellermainip?user='+username+'&ip='+ip)

        def suspendReseller(self, username, reason=""):
                """Suspend a reseller's account.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/SuspendReseller
                """
                return self.cQuery('suspendreseller?user='+username+'&reason='+reason)

        def unsuspendReseller(self, username):
                """Unsuspend a reseller's account.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/UnsuspendReseller
                """
                return self.cQuery('unsuspendreseller?user='+username)

        def setResellerNameservers(self, username, nameservers=""):
                """Define a reseller's nameservers.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/SetResellerNameservers
                """
                return self.cQuery('setresellernameservers?user='+username+'&nameservers='+nameservers)

        def listResellerAccounts(self, username):
                """Lists the total number of accounts owned by a reseller.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/AcctCounts
                """
                return self.cQuery('acctcounts?user='+username)

        # Server Functions

        def getServerHostname(self):
                """Lists the server's hostname.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/DisplayServerHostname
                """
                return self.cQuery('gethostname')

        def getServerVersion(self):
                """Displays the version of cPanel & WHM running on the server.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/DisplaycPanelWHMVersion
                """
                return self.cQuery('version')

        def getServerLoads(self):
                """Displays your server's load average.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/LoadAvg
                """
                return self.cQuery('loadavg')

        def getServerLoadsDetailed(self):
                """Calculates and returns the system's load average.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/XmlSystemLoadAvg
                """
                return self.cQuery('systemloadavg?api.version=1')

        def getServerLanguages(self):
                """Retrieves a list of the languages available on your server.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/GetLangList
                """
                return self.cQuery('getlanglist')

        # Server Administration Functions

        def rebootServer(self, force=False):
                """Restart a server gracefully or forcefully.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/RebootServer
                """
                return self.cQuery('reboot?force='+force)

        def addServerIP(self, ips, netmask):
                """Add new IP address(es) to WebHost Manager.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/AddIPs
                """
                return self.cQuery('addips?api.version=1&ips='+ips+'&netmask='+netmask)

        def deleteServerIP(self, ip, *args):
                """Deletes an IP address from the server.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/DeleteIPAddress
                """
                return self.cQuery('delip?ip='+ip)

        def listServerIPs(self):
                """Lists all IP addresses bound to network interfaces on the server.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/ListIPAddresses
                """
                return self.cQuery('listips')

        def setServerHostname(self, hostname):
                """Change the server's hostname.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/SetHostname
                """
                return self.cQuery('sethostname?hostname='+hostname)

        def setServerResolvers(self, nameserver1, nameserver2="", nameserver3=""):
                """Configures the nameservers that your server will use to resolve domain names.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/SetResolvers
                """
                return self.cQuery('setresolvers?nameserver1='+nameserver1+'&nameserver2='+nameserver2+'&nameserver3='+nameserver3)

        def showBandwidthUsage(self, *args):
                """Displays bandwidth information by account.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/ShowBw
                """
                return self.cQuery('showbw')

        def setNvVar(self, nvkey, nvval):
                """Create "non-volatile" variables and values, setting them to anything you wish.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/NvSet
                """
                return self.cQuery('nvset?key='+nvkey+'&value='+nvval)

        def getNvVar(self, nvkey):
                """View the value of a non-volatile variable.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/NvGet
                """
                return self.cQuery('nvget?key='+nvkey)

        def setServerSupportTier(self, tier="stable"):
                """Sets your server to the specified support tier.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/SetTier
                """
                return self.cQuery('getpkginfo?tier='+tier)

        def getServerSupportTier(self):
                """Lists all available support tiers of cPanel and WHM.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/GetAvailabletiers -
                This function will retrieve a
                """
                return self.cQuery('get_available_tiers')

        def generateAccessHash(self, *args):
                """Retrieve an access hash for the root user.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/AccessHash
                """
                return self.cQuery('accesshash?api.version=1')

        def getKeyDocuments(self, module, key, section=""):
                """Retrieves documentation about a key referenced within a specified module.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/FetchDocKey
                """
                return self.cQuery('fetch_doc_key?module='+module+'&key='+key)

        def validateEximConfigSpecified(self, cfg_text, section=""):
                """Evaluates and validate Exim configuration file syntax.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/EximValidateSyntax
                """
                return self.cQuery('validate_exim_configuration_syntax?cfg_text='+cfg_text)

        def validateEximConfig(self):
                """Validates the system's current Exim configuration.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/EximValidateConfig
                """
                return self.cQuery('validate_current_installed_exim_config')

        def checkRepairEximConfig(self):
                """Checks and, if it encounters any errors, attempt to repair your Exim configuration.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/EximConfigurationCheck
                """
                return self.cQuery('exim_configuration_check')

        def removeInProgressEximEdit(self):
                """Removes dry run files after a failed Exim update attempt.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/EximRemoveDryRunConfig
                """
                return self.cQuery('remove_in_progress_exim_config_edit')

        def getTweakSettingsValue(self, key, module="Main"):
                """Retrieve the value of an option available on the WHM Tweak Settings screen.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/GetTweakSetting
                """
                return self.cQuery('get_tweaksetting?api.version=1&key='+key+'&module='+module)

        def setTweakSettingsValue(self, key, val, module="Main"):
                """Change the value of an option available on the WHM Tweak Settings screen.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/SetTweakSetting
                """
                return self.cQuery('set_tweaksetting?api.version=1&key='+key+'&value='+val+'&module='+module)

        def getDeliveryRecords(self, *args):
                """Retrieves email delivery records.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/EmailTrackSearch -
                """
                return self.cQuery('emailtrack_search?api.version=1')

        def setServerUpdateFrequency(self, updates="manual"):
                """Sets the frequency that updates will run on the server.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/SetCpanelupdates
                """
                return self.cQuery('set_cpanel_updates?updates='+updates)

        def getAppConfigApps(self):
                """Lists applications that are registered with AppConfig.
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/GetAppconfigapplicationlist
                """
                return self.cQuery('get_appconfig_application_list')
