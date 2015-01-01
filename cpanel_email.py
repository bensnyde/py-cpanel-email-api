
"""

Python Library for WHM/Cpanel's API2 Email Module

    https://documentation.cpanel.net/display/SDK/cPanel+API+2+-+Email

Author: Benton Snyder
Website: http://bensnyde.me
Created: 8/15/13
Revised: 1/1/15

"""
import base64
import httplib
import json
import logging
import socket

# Log handler
apilogger = "apilogger"

class Cpanel:
    def __init__(self, whm_base_url, whm_root_user, whm_root_password, cpanel_user):
            """Constructor

                Cpanel Email library public constructor.

            Parameters
                :param whm_base_url: str whm base url (ex. whm.example.com)
                :param whm_root_user: str whm root username
                :param whm_root_password: str whm password
                :param cpanel_user: str cpanel account to run scripts as
            Returns
                None
            """
            self.cpanel_user = cpanel_user
            self.whm_base_url = whm_base_url
            self.whm_root_user = whm_root_user
            self.whm_root_password = whm_root_password

    def _whm_api_query(self, script, **kwargs):
            """Query WHM API

                Queries specified WHM server's JSON API with specified query string.

            Parameters
                :param script: Cpanel script name
                :param user: Cpanel username underwhich to call from
                :param kwargs: Dictionary parameter pairs
            Returns
                :returns: json decoded response from server
            """
            query = '/json-api/cpanel?cpanel_jsonapi_user=%s&cpanel_jsonapi_module=Email&cpanel_jsonapi_func=%s&cpanel_xmlapi_version=2&' % (self.cpanel_user, script)

            try:
                conn = httplib.HTTPSConnection(self.whm_base_url, 2087)
                conn.request('GET', '/json-api/%s' % query, headers={'Authorization':'Basic ' + base64.b64encode(self.whm_root_user+':'+self.whm_root_password).decode('ascii')})
                response = conn.getresponse()
                data = json.loads(response.read())
                conn.close()

                return data
            except httplib.HTTPException as ex:
                logging.getLogger(apilogger).critical("HTTPException from CpanelEmail API: %s" % ex)
            except socket.error as ex:
                logging.getLogger(apilogger).critical("Socket.error connecting to CpanelEmail API: %s" % ex)
            except ValueError as ex:
                logging.getLogger(apilogger).critical("ValueError decoding CpanelEmail API response string: %s" % ex)
            except Exception as ex:
                logging.getLogger(apilogger).critical("Unhandled Exception while querying CpanelEmail API: %s" % ex)


    def addpop(self, domain, email, password, quota):
        """Add Email Account

            Adds a new email account.

                   https://documentation.cpanel.net/display/SDK/cPanel+API+2+-+Email#cPanelAPI2-Email-Email::addpop

           Parameters
            :param domain: The domain for the new email account
            :param email: The username for the new email account
            :param password: The password for the new email account
            :param quota: A positive integer that defines the disk quota for the email account (0 is unlimited)
        Returns
            :returns: bool api call result
        """
        data = {
                'domain': domain,
                'email': email,
                'password': password,
                'quota': quota
            }

        result = self._whm_api_query('addpop', **data)

        try:
            if result["cpanelresult"]["data"][0]["result"] == 1:
                return True
        except Exception as ex:
            logging.getLogger(apilogger).error('addpop(%s) returned unexpected result: %s' % (data, ex))

        return False


    def delpop(self, domain, email):
        """Delete Email Account

            Deletes an email account.

                https://documentation.cpanel.net/display/SDK/cPanel+API+2+-+Email#cPanelAPI2-Email-Email::delpop

        Parameters
            :param domain: The domain for the email account you wish to remove
            :param email: The username for the email address you wish to remove
        Returns
            :returns: bool api call result
        """
        data = {
            'domain': domain,
            'email': email
        }

        result = self._whm_api_query('delpop', **data)

        try:
            if result["cpanelresult"]["data"][0]["result"] == 1:
                return True
        except Exception as ex:
            logging.getLogger(apilogger).error('delpop(%s) returned unexpected result: %s' % (data, ex))

        return False


    def editquota(self, domain, email, quota):
        """Edit Quota

            Modifies an email account's quota.

                https://documentation.cpanel.net/display/SDK/cPanel+API+2+-+Email#cPanelAPI2-Email-Email::editquota

        Parameters
            :param domain: The domain for the email account you wish to modify
            :param email: The username for the email address you wish to modify
            :param quota: A positive integer that indicates the desired disk quota value in megabytes (0 is unlimited)
        Returns
            :returns: bool api call result
        """
        data = {
            'domain': domain,
            'email': email,
            'quota': quota
        }

        result = self._whm_api_query('editquota', **data)

        try:
            if result["cpanelresult"]["data"][0]["result"] == 1:
                return True
        except Exception as ex:
            logging.getLogger(apilogger).error('editquota(%s) returned unexpected result: %s' % (data, ex))

        return False


    def passwdpop(self, domain, email, password):
        """Change Password

            Changes an email account's password.

                https://documentation.cpanel.net/display/SDK/cPanel+API+2+-+Email#cPanelAPI2-Email-Email::passwdpop=

        Parameters
            :param domain: The domain for the email address for which you wish to change the password
            :param email: The username for the email address for which you wish to change the password
            :param password: The desired password for the account
        Returns
            :returns: bool api call result
        """
        data = {
            'domain': domain,
            'email': email,
            'password': password,
        }

        result = self._whm_api_query('passwdpop', **data)

        try:
            if result["cpanelresult"]["data"][0]["result"] == 1:
                return True
        except Exception as ex:
            logging.getLogger(apilogger).error('passwdpop(%s) returned unexpected result: %s' % (data, ex))

        return False


    def clearpopcache(self, username):
        """Clear Email Account Cache

            Rebuilds an email address's cache file.

                https://documentation.cpanel.net/display/SDK/cPanel+API+2+-+Email#cPanelAPI2-Email-Email::clearpopcache

        Parameters
            :param username: The username for the email account for which you wish to rebuild the cache file
        Returns
            :returns: bool api call result
        """
        result = self._whm_api_query('clearpopcache', **{'username': username} )

        try:
            if result["cpanelresult"]["data"][0]["result"] == 1:
                return True
        except Exception as ex:
            logging.getLogger(apilogger).error('clearpopcache(%s) returned unexpected result: %s' % (username, ex))

        return False


    def listpops(self, regex=None):
        """List Email Accounts

            Retrieves a list of email accounts associated with your cPanel account.

                https://documentation.cpanel.net/display/SDK/cPanel+API+2+-+Email#cPanelAPI2-Email-Email::listpops

        Parameters
            :param regex: The regular expression by which you wish to filter the results
        Returns
            :returns: json formatted string
        """
        data = {}
        if regex:
            data['regex'] = regex

        result = self._whm_api_query('listpops', **data)

        try:
            if result["cpanelresult"]["event"]["result"] == 1:
                return result["cpanelresult"]["data"]
        except Exception as ex:
            logging.getLogger(apilogger).error('listpops(%S) returned unexpected result: %s' % (data, ex))

        return False


    def listpopssingles(self, regex=None):
        """List Email Accounts w/Logins

            Retrieves a list of email accounts and logins associated with your cPanel account.

                https://documentation.cpanel.net/display/SDK/cPanel+API+2+-+Email#cPanelAPI2-Email-Email::listpopssingles

        Parameters
            :param regex: The regular expression by which you wish to filter the results
        Returns
            :returns: json formatted string
        """
        data = {}
        if regex:
            data['regex'] = regex

        result = self._whm_api_query('listpopssingles', **data)

        try:
            if result["cpanelresult"]["data"][0]["result"] == 1:
                return result["cpanelresult"]["data"]
        except Exception as ex:
            logging.getLogger(apilogger).error('listpopssingles(%s) returned unexpected result: %s' % (data, ex))

        return False


    def listpopswithdisk(self, domain=None, nearquotaonly=False, no_validate=False, regex=None):
        """List Email Accounts w/Disk Usage

            Lists email accounts, including disk usage, that correspond to a particular domain.

                https://documentation.cpanel.net/display/SDK/cPanel+API+2+-+Email#cPanelAPI2-Email-Email::listpopswithdisk

        Parameters
            :param domain: The domain for which you wish to view email accounts
            :param nearquotaonly: If you pass 1 to this parameter, you will only view accounts that use 95% or more of their allotted disk space
            :param no_validate: If you pass 1 to this parameter, the function only reads data from your .cpanel/email_accounts.yaml file.
            :param regex: The regular expression by which you wish to filter the results
        Returns
            :returns: json formatted string
        """
        data = {
            'nearquotaonly': nearquotaonly,
            'no_validate': no_validate
        }

        if domain:
            data['domain'] = domain
        if regex:
            data['regex'] = regex

        result = self._whm_api_query('listpopswithdisk', **data)

        try:
            if result["cpanelresult"]["data"][0]["result"] == 1:
                return result["cpanelresult"]["data"]
        except Exception as ex:
            logging.getLogger(apilogger).error('listpopswithdisk(%s) returned unexpected result: %s' % ex)

        return False


    def accountname(self, account, display):
        """Get Account Name

            Displays the account name or All Mail On Your Account.

            https://documentation.cpanel.net/display/SDK/cPanel+API+2+-+Email#cPanelAPI2-Email-Email::accountname

        Parameters
            :param account: Specifies the account name or email address. The function will return whichever of these values you do not specify.
            :param display: If present, and you do not specify an account, the function will return the string All Mail On Your Account.
        Returns
            :returns: json formatted string
        """
        data = {
            'account': account,
            'display': display
        }

        result = self._whm_api_query('accountname', **data)

        try:
            if result["cpanelresult"]["data"][0]["result"] == 1:
                return result["cpanelresult"]["data"]
        except Exception as ex:
            logging.getLogger(apilogger).error('accountname(%s) returned unexpected result: %s' % ex)

        return False


    def getdiskusage(self, domain, user):
        """Get Email Account Disk Usage

            Retrieves information about a specified email account's disk usage.

                https://documentation.cpanel.net/display/SDK/cPanel+API+2+-+Email#cPanelAPI2-Email-Email::getdiskusage

        Parameters
            :param domain: The domain that corresponds to the email address for which you wish to view disk usage
            :param user: The username of the email address for which you wish to view disk usage
        Returns
            :returns: json formatted string
        """
        data = {
            'domain': domain,
            'user': user
        }

        result = self._whm_api_query('getdiskusage', **data)

        try:
            if result["cpanelresult"]["data"][0]["result"] == 1:
                return result["cpanelresult"]["data"]
        except Exception as ex:
            logging.getLogger(apilogger).error('getdiskusage(%s) returned unexpected result: %s' % ex)

        return False


    def listmaildomains(self, skipmain=True):
        """Get Email Domains

            Retrieves a list of the domains associated with your account that send and receive email.

                https://documentation.cpanel.net/display/SDK/cPanel+API+2+-+Email#cPanelAPI2-Email-Email::listmaildomains

        Parameters
            :param skipmain: Pass 1 to this variable to skip the main domain
        Returns
            :returns: json formatted string
        """
        result = self._whm_api_query('listmaildomains', **{'skipmain': skipmain})

        try:
            if result["cpanelresult"]["data"][0]["result"] == 1:
                return result["cpanelresult"]["data"]
        except Exception as ex:
            logging.getLogger(apilogger).error('listmaildomains(%s) returned unexpected result: %s' % (skipmain, ex))

        return False


    def listlists(self, domain=None, regex=None):
        """Get Mailing Lists

            Lists mailing lists associated with a domain.

                https://documentation.cpanel.net/display/SDK/cPanel+API+2+-+Email#cPanelAPI2-Email-Email::listlists

        Parameters
            :param domain: The domain for which you wish to view a list of mailing lists
            :param regex: The regular expression by which you wish to filter the results
        Returns
            :returns: json formatted string
        """
        data = {}
        if domain:
            data['domain'] = domain
        if regex:
            data['regex'] = regex

        result = self._whm_api_query('listlists', **data)

        try:
            if result["cpanelresult"]["data"][0]["result"] == 1:
                return result["cpanelresult"]["data"]
        except:
            logging.getLogger(apilogger).error('listlists(%s) returned unexpected result: %s' % (data, ex))

        return False


    def setdefaultaddress(self, fwdopt, domain, failmsgs=None, fwdemail=None, pipefwd=None):
        """Set Default Email Address

            Configure a default (catchall) email address.

            https://documentation.cpanel.net/display/SDK/cPanel+API+2+-+Email#cPanelAPI2-Email-Email::setdefaultaddress

        Parameters
            :param fwdopt: This parameter defines how unroutable mail will be handled.
            :param domain: Specifies the domain to which you wish to apply the rule.
            :param failmsgs: Specifies the failure message that you wish to send if an incoming message bounces.
            :param fwdemail: Specifies the email address to which mail received by the default address is forwarded.
            :param pipefwd: Specifies the program to which messages received by the default address are piped
        Returns
            :returns: bool api call result
        """
        data = {
            'fwdopt': fwdopt,
            'domain': domain
        }

        if failmsgs:
            data['failmsgs'] = failmsgs
        if fwdemail:
            data['fwdemail'] = fwdemail
        if pipefwd:
            data['pipefwd'] = pipefwd

        result = self._whm_api_query('setdefaultaddress', **data)

        try:
            if result["cpanelresult"]["data"][0]["result"] == 1:
                return True
        except Exception as ex:
            logging.getLogger(apilogger).error('setdefaultaddress(%s) returned unexpected result: %s' % (data, ex))

        return False


    def checkmaindiscard(self):
        """Get Discard Settings

            Checks how the main email account for a domain handles undeliverable mail.

                https://documentation.cpanel.net/display/SDK/cPanel+API+2+-+Email#cPanelAPI2-Email-Email::checkmaindiscard

        Parameters
            None
        Returns
            :returns: json formatted string
        """
        result = self._whm_api_query('checkmaindiscard', **{})

        try:
            if result["cpanelresult"]["data"][0]["result"] == 1:
                return result["cpanelresult"]["data"]
        except Exception as ex:
            logging.getLogger(apilogger).error('checkmaindiscard() returned unexpected result: %s' % ex)

        return False


    def listdefaultaddresses(self, domain):
        """Get Default Addresses

            Retrieves the default address and the action taken when the default address receives unroutable messages.

                https://documentation.cpanel.net/display/SDK/cPanel+API+2+-+Email#cPanelAPI2-Email-Email::listdefaultaddresses

           Parameters
            :param domain: The domain that corresponds to the default address and information you wish to view
        Returns
            :returns: json formatted string
        """
        result = self._whm_api_query('listdefaultaddresses', **{'domain': domain})

        try:
            if result["cpanelresult"]["data"][0]["result"] == 1:
                return result["cpanelresult"]["data"]
        except Exception as ex:
            logging.getLogger(apilogger).error('listdefaultaddresses(%s) returned unexpected result: %s' % (domain, ex))

        return False


    def listaliasbackups(self):
        """Get Domains w/Aliases

            Retrieves a list of domains that use aliases and custom catch-all addresses.

                https://documentation.cpanel.net/display/SDK/cPanel+API+2+-+Email#cPanelAPI2-Email-Email::listaliasbackups

        Parameters
            None
        Returns
            :returns: json formatted string
        """
        result = self._whm_api_query('listaliasbackups', **{})

        try:
            if result["cpanelresult"]["data"][0]["result"] == 1:
                return result["cpanelresult"]["data"]
        except Exception as ex:
            logging.getLogger(apilogger).error('listaliasbackups() returned unexpected result: %s' % ex)

        return False


    def addforward(self, domain, email, fwdopt, fwdemail=None, fwdsystem=None, failmsgs=None, pipefwd=None):
        """Add Forward

            Creates an email forwarder for the specified address.

                https://documentation.cpanel.net/display/SDK/cPanel+API+2+-+Email#cPanelAPI2-Email-Email::addforward

        Parameters
            :param domain: The domain for which you wish to add a forwarder
            :param email: The username of the email address for which you wish to add a forwarder
            :param fwdopt: This parameter defines how unroutable mail will be handled.
            :param fwdemail: The email address to which you wish to forward mail. Use this parameter when fwdopt=fwd.
            :param fwdsystem: The system account to which you wish to forward email. Use this parameter when fwdopt=system.
            :param failmsgs: Use this parameter to define the correct failure message. Use this parameter when fwdopt=fail.
            :param pipefwd: The path to the program to which you wish to pipe email. Use this parameter when fwdopt=pipe.
        Returns
            :returns: bool api call result
        """
        data = {
            'email': email,
            'fwdopt': fwdopt,
        }

        if fwdemail:
            data['fwdemail'] = fwdemail
        if fwdsystem:
            data['fwdsystem'] = fwdsystem
        if failmsgs:
            data['failmsgs'] = failmsgs
        if pipefwd:
            data['pipefwd'] = pipefwd

        result = self._whm_api_query('addforward', **data)

        try:
            if result["cpanelresult"]["data"][0]["result"] == 1:
                return True
        except Exception as ex:
            logging.getLogger(apilogger).error('addforward(%s) returned unexpected result: %s' % (data, ex))

        return False


    def listforwards(self, domain=None, regex=None):
        """Get Forwards

            List forwarders associated with a specific domain.

                https://documentation.cpanel.net/display/SDK/cPanel+API+2+-+Email#cPanelAPI2-Email-Email::listforwards=

        Parameters
            :param domain: The domain name for which you wish to review forwarders
            :param regex: The regular expression by which you wish to filter the results
        Returns
            :returns: json formatted string
        """
        data = {}
        if domain:
            data['domain'] = domain
        if regex:
            data['regex'] = regex

        result = self._whm_api_query('listforwards', **data)

        try:
            if result["cpanelresult"]["event"]["result"] == 1:
                return result["cpanelresult"]["data"]
        except Exception as ex:
            logging.getLogger(apilogger).error('listforwards(%s) returned unexpected result: %s' % ex)

        return False


    def listdomainforwards(self, domain):
        """Get Domain Forwards

            Retrieves the destination to which a domain forwarder forwards email.
        
                https://documentation.cpanel.net/display/SDK/cPanel+API+2+-+Email#cPanelAPI2-Email-Email::listdomainforwards=

        Parameters
            :param domain: The domain that corresponds to the forwarder for which you wish to view the destination
        Returns
            :returns: json formatted string
        """
        result = self._whm_api_query('listdomainforwards', **{'domain': domain})

        try:
            if result["cpanelresult"]["data"][0]["result"] == 1:
                return result["cpanelresult"]["data"]
        except Exception as ex:
            logging.getLogger(apilogger).error('Failed to listdomainforwards(%s): %s' % (domain, ex))

        return False


    def storefilter(self, account, action, filtername, match, part, val, opt="or", dest=None, oldfiltername=None):
        """Create Email Filter

            Creates a new email filter.

                https://documentation.cpanel.net/display/SDK/cPanel+API+2+-+Email#cPanelAPI2-Email-Email::storefilter=

        Parameters
            :param account: To configure a user-level filter, enter the email address to which you wish to apply the rule.
            :param action: Specifies the action that the filter takes.
            :param filtername: Specifies the name you wish to give to the new filter
            :param match:  Specifies the new filter match type.
            :param part: The section of the email to which you wish to apply the match parameter.
            :param val: Specifies the value against which you wish to match.
            :param opt: This parameter connects conditionals.
            :param oldfiltername: This function can also be used to rename an existing filter.
            :param dest: Specifies the destination of mail that the filter receives, if one is required.
        Returns
            :returns: json formatted string
        """
        data = {
            'account': account,
            'action': action,
            'filtername': filtername,
            'match': match,
            'opt': opt,
            'part': part,
            'val': val
        }

        if dest:
            data['dest'] = dest
        if oldfiltername:
            data['oldfiltername'] = oldfiltername

        result = self._whm_api_query('storefilter', **data)

        try:
            if result["cpanelresult"]["data"][0]["result"] == 1:
                return result["cpanelresult"]["data"]
        except Exception as ex:
            logging.getLogger(apilogger).error('storefilter(%s) returned unexpected result: %s' % (data, ex))

        return False


    def deletefilter(self, filtername, account=None):
        """Delete Email Filter

            Deletes an email filter.
        
                https://documentation.cpanel.net/display/SDK/cPanel+API+2+-+Email#cPanelAPI2-Email-Email::deletefilter=

        Parameters
            :param filtername: Specifies the name of the filter you wish to delete.
            :param account: Specifies an email address or account username that corresponds to the user-level filter you wish to remove.
        Returns
            :returns: bool api call result
        """
        data = {'filtername': filtername}
        if account:
            data['account'] = account

        result = self._whm_api_query('deletefilter', **data)

        try:
            if result["cpanelresult"]["data"][0]["result"] == 1:
                return True
        except Exception as ex:
            logging.getLogger(apilogger).error('deletefilter(%s) returned unexpected result: %s' % (data, ex))

        return False


    def tracefilter(self, msg, account=None):
        """Trace Email Filter

            Tests the action of account-level mail filters.

                https://documentation.cpanel.net/display/SDK/cPanel+API+2+-+Email#cPanelAPI2-Email-Email::tracefilter=

        Parameters
            :param msg: The contents of the body of the message you wish to test.
            :param account: This parameter allows you to specify and test old-style cPanel filters in the $home/filters directory.
        Returns
            :returns: json formatted string
        """
        data = {'msg': msg}
        if account:
            data['account'] = account

        result = self._whm_api_query('tracefilter', **data)

        try:
            if result["cpanelresult"]["data"][0]["result"] == 1:
                return result["cpanelresult"]["data"]
        except Exception as ex:
            logging.getLogger(apilogger).error('tracefilter(%s) returned unexpected result: %s' % ex)

        return False


    def filterlist(self, account=None):
        """Get Email Filters

            Retrieves a list of email filters.

                https://documentation.cpanel.net/display/SDK/cPanel+API+2+-+Email#cPanelAPI2-Email-Email::filterlist=

        Parameters
            :param account: Specifies the email address or account username.
        Returns
            :returns: json formatted string
        """
        data = {}
        if account:
            data['account'] = account

        result = self._whm_api_query('filterlist', **data)

        try:
            if result["cpanelresult"]["data"][0]["result"] == 1:
                return result["cpanelresult"]["data"]
        except Exception as ex:
            logging.getLogger(apilogger).error('filterlist(%s) returned unexpected result: %s' % ex)

        return False


    def loadfilter(self, filtername, account=None):
        """Load Email Filter

            Retrieves the rules and actions associated with an email filter.

                https://documentation.cpanel.net/display/SDK/cPanel+API+2+-+Email#cPanelAPI2-Email-Email::loadfilter=

        Parameters
            :param filtername: Specifies the name of the filter you wish to review.
            :param account: Specifies the email address or account username.
        Returns
            :returns: json formatted string
        """
        data = {'filtername': filtername}
        if account:
            data['account'] = account

        result = self._whm_api_query('loadfilter', **data)

        try:
            if result["cpanelresult"]["data"][0]["result"] == 1:
                return result["cpanelresult"]["data"]
        except Exception as ex:
            logging.getLogger(apilogger).error('loadfilter(%s) returned unexpected result: %s' % (data, ex))

        return False


    def filtername(self, account=None, filtername=None):
        """Get Suggested Filter Name

            Counts the number of email filters and returns a default suggested rule name in a Rule [1 + count] format.

                https://documentation.cpanel.net/display/SDK/cPanel+API+2+-+Email#cPanelAPI2-Email-Email::filtername=

        Parameters
            :param account: Specifies the email address associated with the account for which you wish to return a result.
            :param filtername: Specifies a fallback in the case that the function cannot find any relevant filter files.
        Returns
            :returns: json formatted string
        """
        data = {}
        if account:
            data['account'] = account
        if filtername:
            data['filtername'] = filtername

        result = self._whm_api_query('filtername', **data)

        try:
            if result["cpanelresult"]["data"][0]["result"] == 1:
                return result["cpanelresult"]["data"]
        except Exception as ex:
            logging.getLogger(apilogger).error('filtername(%s) returned unexpected result: %s' % (data, ex))

        return False


    def listfilterbackups(self):
        """Get Domains With Domain Filters

            Retrieves a list of domains that use domain-level filters.

                https://documentation.cpanel.net/display/SDK/cPanel+API+2+-+Email#cPanelAPI2-Email-Email::listfilterbackups=

        Parameters
            None
        Returns
            :returns: json formatted string
        """
        result = self._whm_api_query('listfilterbackups', **{})

        try:
            if result["cpanelresult"]["data"][0]["result"] == 1:
                return result["cpanelresult"]["data"]
        except Exception as ex:
            logging.getLogger(apilogger).error('listfilterbackups() returned unexpected result: %s' % ex)

        return False


    def listfilters(self):
        """Get Email Filters

            Lists all of the old-style email filters in your .filter file.

                https://documentation.cpanel.net/display/SDK/cPanel+API+2+-+Email#cPanelAPI2-Email-Email::listfilters=

        Parameters
            None
        Returns
            :returns: json formatted string
        """
        result = self._whm_api_query('listfilters', **{})

        try:
            if result["cpanelresult"]["data"][0]["result"] == 1:
                return result["cpanelresult"]["data"]
        except Exception as ex:
            logging.getLogger(apilogger).error('listfilters() returned unexpected result: %s' % ex)

        return False


    def listautoresponders(self, domain=None, regex=None):
        """Get Auto Responders

            Retrieves a list of auto responders associated with the specified domain.

                https://documentation.cpanel.net/display/SDK/cPanel+API+2+-+Email#cPanelAPI2-Email-Email::listautoresponders=

        Parameters
            :param domain: The domain for which you wish to view auto responders
            :param regex: Regular expressions allow you to filter results based on a set of criteria
        Returns
            :returns: json formatted string
        """
        data = {}
        if domain:
            data['domain'] = domain
        if regex:
            data['regex'] = regex

        result = self._whm_api_query('listautoresponders', **data)

        try:
            if result["cpanelresult"]["data"][0]["result"] == 1:
                return result["cpanelresult"]["data"]
        except Exception as ex:
            logging.getLogger(apilogger).error('listautoresponders(%s): %s' % (data, ex))

        return False


    def fetchautoresponder(self, email):
        """Get Auto Responder

            Retrieves information about an auto responder that corresponds to a specified email address.

                https://documentation.cpanel.net/display/SDK/cPanel+API+2+-+Email#cPanelAPI2-Email-Email::fetchautoresponder=

        Parameters
            :param email: The email address that corresponds to the auto responder you wish to review
        Returns
            :returns: json formatted string
        """
        result = self._whm_api_query('fetchautoresponder', **{'email': email})

        try:
            if result["cpanelresult"]["event"]["result"] == 1:
                return result["cpanelresult"]["data"]
        except Exception as ex:
            logging.getLogger(apilogger).error('Failed to fetchautoresponder(%s) returned unexpected result: %s' % (email, ex))

        return False


    def set_archiving_configuration(self, domain, dtype):
        """Sets the email archiving configuration for the specified domain.
        https://documentation.cpanel.net/display/SDK/cPanel+API+2+-+Email#cPanelAPI2-Email-Email::set_archiving_configuration=

        Parameters
        :param domains: A comma separated list of domains for which you wish to change the configuration
        :param type: An integer, or empty-string, value that indicates the length of time to keep mail archives of the given type.
        Returns
        :returns: json formatted string
        """
        data = {
            'domain': domain,
            'type': dtype
        }

        result = self._whm_api_query('set_archiving_configuration', **data)

        try:
            if result["cpanelresult"]["data"][0]["result"] == 1:
                return result["cpanelresult"]["data"]
        except Exception as ex:
            logging.getLogger(apilogger).error('set_archiving_configuration(%s) returned unexpected result: %s' % ex)

        return False


    def set_archiving_default_configuration(self, dtype):
        """Set Archiving Configuration

            Sets the default email archiving configuration for any new domains created under the user account.

                https://documentation.cpanel.net/display/SDK/cPanel+API+2+-+Email#cPanelAPI2-Email-Email::set_archiving_default_configuration=

        Parameters
            :param type: An integer, or empty-string, value that indicates the length of time to keep mail archives of the given type.
        Returns
            :returns: json formatted string
        """
        result = self._whm_api_query('set_archiving_default_configuration', **{'type': dtype})

        try:
            if result["cpanelresult"]["data"][0]["result"] == 1:
                return result["cpanelresult"]["data"]
        except Exception as ex:
            logging.getLogger(apilogger).error('Failed to set_archiving_default_configuration(%s): %s' % (dtype, ex))

        return False


    def get_archiving_configuration(self, domain=None, regex=None):
        """Get Archiving Configuration

            Lists the email archiving configuration for the specified domain.

                https://documentation.cpanel.net/display/SDK/cPanel+API+2+-+Email#cPanelAPI2-Email-Email::get_archiving_configuration=

        Parameters
            :param domain: The domain name for which you wish to view email archiving configuration information
            :param regex: A case-sensitive regular expression used to filter by domain
        Returns
            :returns: json formatted string
        """
        data = {}
        if domain:
            data['domain'] = domain
        if regex:
            data['regex'] = regex

        result = self._whm_api_query('get_archiving_configuration', **data)

        try:
            if result["cpanelresult"]["data"][0]["result"] == 1:
                return result["cpanelresult"]["data"]
        except Exception as ex:
            logging.getLogger(apilogger).error('get_archiving_configuration(%s) returned unexpected result: %s' % (data, ex))

        return False


    def get_archiving_default_configuration(self, domain):
        """Get Default Archiving Configuration

            Lists the default email archiving configuration for the specified domain.

                https://documentation.cpanel.net/display/SDK/cPanel+API+2+-+Email#cPanelAPI2-Email-Email::get_archiving_default_configuration=

        Parameters
            :param domain: The domain for which you wish to view the default configuration
        Returns
            :returns: json formatted string
        """
        result = self._whm_api_query('get_archiving_default_configuration', **{'domain': domain})

        try:
            if result["cpanelresult"]["data"][0]["result"] == 1:
                return result["cpanelresult"]["data"]
        except Exception as ex:
            logging.getLogger(apilogger).error('get_archiving_default_configuration(%s) returned unexpected result: %s' % (domain, ex))

        return False


    def get_archiving_types(self):
        """Get Archiving Typse

            Displays the different types of email archiving that are available.

                https://documentation.cpanel.net/display/SDK/cPanel+API+2+-+Email#cPanelAPI2-Email-Email::get_archiving_types=

        Parameters
            None
        Returns
            :returns: json formatted string
        """
        result = self._whm_api_query('get_archiving_types', **{})

        try:
            if result["cpanelresult"]["data"][0]["result"] == 1:
                return result["cpanelresult"]["data"]
        except Exception as ex:
            logging.getLogger(apilogger).error('get_archiving_types() returned unexpected result: %s' % ex)

        return False


    def getabsbrowsedir(separatedlf, account, adir="mail"):
        """Get Mail Folder Path

            Retrieves the full path to a specified mail folder.

                https://documentation.cpanel.net/display/SDK/cPanel+API+2+-+Email#cPanelAPI2-Email-Email::getabsbrowsedir=

        Parameters
            :param account: The email address that corresponds to the directory for which you wish to find the path
            :param dir: The mail folder that you wish to query for its full path
        Returns
            :returns: json formatted string
        """
        data = {
            'account': account,
            'dir': adir
        }

        result = self._whm_api_query('getabsbrowsedir', **data)

        try:
            if result["cpanelresult"]["data"][0]["result"] == 1:
                return result["cpanelresult"]["data"]
        except Exception as ex:
            logging.getLogger(apilogger).error('getabsbrowserdir(%s) returned unexpected result: %s' % (data, ex))

        return False


    def browseboxes(self, account=None, adir="default", showdotfiles=False):
        """Get Mailboxes

            Retrieves a list of mail-related subdirectories (boxes) in your mail directory.

                https://documentation.cpanel.net/display/SDK/cPanel+API+2+-+Email#cPanelAPI2-Email-Email::browseboxes=

        Parameters
            :param account: The name of the email account you wish to review
            :param dir:str = This parameter allows you to specify which mail directories will be displayed.
            :param showdotfiles: A boolean variable that allows you to specify whether you wish to view hidden directories and files
        Returns
            :returns: json formatted string
        """
        data = {
            'dir': adir,
            'showdotfiles': showdotfiles
        }

        if account:
            data['account'] = account

        result = self._whm_api_query('browseboxes', **data)

        try:
            if result["cpanelresult"]["data"][0]["result"] == 1:
                return result["cpanelresult"]["data"]
        except Exception as ex:
            logging.getLogger(apilogger).error('browseboxes(%s) returned unexpected result: %s' % (data, ex))

        return False
