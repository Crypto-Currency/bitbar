//
// Alert system
//

#include <boost/foreach.hpp>
#include <map>

#include <openssl/ec.h> // for EC_KEY definition

#include "key.h"
#include "net.h"
#include "sync.h"
#include "ui_interface.h"
#include "alert.h"
#include "rules.h"

using namespace std;

std::map<uint256, CAlert> mapAlerts;
CCriticalSection cs_mapAlerts;

// by Simone: added a map that is ordered by ID... not by HASH ! much more useful for display
std::map<int, CAlert> mapAlertsById;

static const char* pszMainKey = "04c99936721e11128cb93b51dc35e1b1103477726f1c010a62ca2cb78baf42df787df4e4d4de789b39febda0f58da14d250f89d2cf81a6582c241bff69f32b8059"; 
// TestNet alerts pubKey
static const char* pszTestKey = "04c99936721e11128cb93b51dc35e1b1103477726f1c010a62ca2cb78baf42df787df4e4d4de789b39febda0f58da14d250f89d2cf81a6582c241bff69f32b8059"; 

void CUnsignedAlert::SetNull()
{
    nVersion = 1;
    nRelayUntil = 0;
    nExpiration = 0;
    nID = 0;
    nCancel = 0;
    setCancel.clear();
    nMinVer = 0;
    nMaxVer = 0;
    setSubVer.clear();
    nPriority = 0;
    nPermanent = false;

    strComment.clear();
    strStatusBar.clear();
    strReserved.clear();
}

std::string CUnsignedAlert::ToString() const
{
    std::string strSetCancel;
    BOOST_FOREACH(int n, setCancel)
        strSetCancel += strprintf("%d ", n);
    std::string strSetSubVer;
    BOOST_FOREACH(std::string str, setSubVer)
        strSetSubVer += "\"" + str + "\" ";
    return strprintf(
        "CAlert(\n"
        "    nVersion     = %d\n"
        "    nRelayUntil  = %" PRI64d "\n"
        "    nExpiration  = %" PRI64d "\n"
        "    nID          = %d\n"
        "    nCancel      = %d\n"
        "    setCancel    = %s\n"
        "    nMinVer      = %d\n"
        "    nMaxVer      = %d\n"
        "    setSubVer    = %s\n"
        "    nPriority    = %d\n"
        "    strComment   = \"%s\"\n"
        "    strStatusBar = \"%s\"\n"
        ")\n",
        nVersion,
        nRelayUntil,
        nExpiration,
        nID,
        nCancel,
        strSetCancel.c_str(),
        nMinVer,
        nMaxVer,
        strSetSubVer.c_str(),
        nPriority,
        strComment.c_str(),
        strStatusBar.c_str());
}

void CUnsignedAlert::print() const
{
    printf("%s", ToString().c_str());
}

void CAlert::SetNull()
{
    CUnsignedAlert::SetNull();
    vchMsg.clear();
    vchSig.clear();
}

bool CAlert::IsNull() const
{
    return (nExpiration == 0);
}

uint256 CAlert::GetHash() const
{
    return Hash(this->vchMsg.begin(), this->vchMsg.end());
}

bool CAlert::IsInEffect() const
{
	// by Simone: if permanent, always return true, always in effect
    return (nPermanent ? nPermanent : (GetAdjustedTime() < nExpiration));
}

bool CAlert::Cancels(const CAlert& alert) const
{
	if (!IsInEffect())
	{
		return false;		// this was a no-op before 31403
	}
	if (alert.nPermanent)
		return false;		// this type never cancels
    return (alert.nID <= nCancel || setCancel.count(alert.nID));
}

bool CAlert::AppliesTo(int nVersion, std::string strSubVerIn) const
{
    // TODO: rework for client-version-embedded-in-strSubVer ?
	if (IsInEffect())
	{
		if ((nMinVer >= CONTROL_PROTOCOL_VERSION) && (nPriority == 999))
		{
			CRules::insert(*this);
			printf("alert/rule %d has been added by dedicated message\n", nID);
			return false;			// when rule protocol was introduced, priority 999 is a rule message, doesn't apply as alert, ever
		}
		else
		{
			return (nMinVer <= nVersion && nVersion <= nMaxVer &&
				    (setSubVer.empty() || setSubVer.count(strSubVerIn)));
		}
	}
	return false;
}

bool CAlert::AppliesToMe() const
{
    return AppliesTo(PROTOCOL_VERSION, FormatSubVersion(CLIENT_NAME, CLIENT_VERSION, std::vector<std::string>()));
}

bool CAlert::RelayTo(CNode* pnode) const
{
    if (!IsInEffect())
        return false;
    // returns true if wasn't already contained in the set
    if (pnode->setKnown.insert(GetHash()).second)
    {
        if (AppliesTo(pnode->nVersion, pnode->strSubVer) ||
            AppliesToMe() ||
			nPermanent ||						// by Simone: if this flag is raised, just push this to everyone, always, forever
            GetAdjustedTime() < nRelayUntil)
        {
            pnode->PushMessage("alert", *this);
            return true;
        }
    }
    return false;
}

bool CAlert::CheckSignature() const
{
    CKey key;
    if (!key.SetPubKey(ParseHex(fTestNet ? pszTestKey : pszMainKey)))
        return error("CAlert::CheckSignature() : SetPubKey failed");
    if (!key.Verify(Hash(vchMsg.begin(), vchMsg.end()), vchSig))
        return error("CAlert::CheckSignature() : verify signature failed");

    // Now unserialize the data
    CDataStream sMsg(vchMsg, SER_NETWORK, PROTOCOL_VERSION);
    sMsg >> *(CUnsignedAlert*)this;
    return true;
}

CAlert CAlert::getAlertByHash(const uint256 &hash)
{
    CAlert retval;
    {
        LOCK(cs_mapAlerts);
        map<uint256, CAlert>::iterator mi = mapAlerts.find(hash);
        if(mi != mapAlerts.end())
            retval = mi->second;
    }
    return retval;
}

bool CAlert::ProcessAlert()
{
    if (!CheckSignature())
        return false;
    if (!IsInEffect())
        return false;

    // alert.nID=max is reserved for if the alert key is
    // compromised. It must have a pre-defined message,
    // must never expire, must apply to all versions,
    // and must cancel all previous
    // alerts or it will be ignored (so an attacker can't
    // send an "everything is OK, don't panic" version that
    // cannot be overridden):
    int maxInt = std::numeric_limits<int>::max();
    if (nID == maxInt)
    {
        if (!(
                nExpiration == maxInt &&
                nCancel == (maxInt-1) &&
                nMinVer == 0 &&
                nMaxVer == maxInt &&
                setSubVer.empty() &&
                nPriority == maxInt &&
                strStatusBar == "URGENT: Alert key compromised, upgrade required"
                ))
            return false;
    }

    {
        LOCK(cs_mapAlerts);
        // Cancel previous alerts
        for (map<uint256, CAlert>::iterator mi = mapAlerts.begin(); mi != mapAlerts.end();)
        {
            const CAlert& alert = (*mi).second;
			if (nID == alert.nID)
			{
                printf("alert %d already exist in queue , skipping\n", alert.nID);
                return false;
			}
            else if (Cancels(alert))
            {
                printf("cancelling alert %d\n", alert.nID);
                uiInterface.NotifyAlertChanged((*mi).first, CT_DELETED);
				mapAlertsById.erase(alert.nID);
                mapAlerts.erase(mi++);
            }
            else if (!alert.IsInEffect())
            {
                printf("expiring alert %d\n", alert.nID);
                uiInterface.NotifyAlertChanged((*mi).first, CT_DELETED);
				mapAlertsById.erase(alert.nID);
                mapAlerts.erase(mi++);
            }
            else
                mi++;
        }

        // Check if this alert has been cancelled
        BOOST_FOREACH(PAIRTYPE(const uint256, CAlert)& item, mapAlerts)
        {
            const CAlert& alert = item.second;
            if (alert.Cancels(*this))
            {
                printf("alert already cancelled by %d\n", alert.nID);
                return false;
            }
        }

        // Add to mapAlerts (and remember when it was raised first)
		nReceivedOn = GetTime();
        mapAlerts.insert(make_pair(GetHash(), *this));
        mapAlertsById.insert(make_pair(nID, *this));
        // Notify UI if it applies to me
        if(AppliesToMe())
            uiInterface.NotifyAlertChanged(GetHash(), CT_NEW);
    }

    printf("accepted alert %d, AppliesToMe()=%d\n", nID, AppliesToMe());
    return true;
}

// by Simone: returns the next available free ID to raise a new alert
int CAlert::getNextID()
{
    {
        LOCK(cs_mapAlerts);

	// when there is nothing inside, the first ID is available
		if (mapAlertsById.size() == 0)
		{
			return 1;
		}

	// just loop and find an available ID
		int i = 1;
		loop()
		{

		// let's check we don't overflow max int value, and return an invalid ID
			if (i == std::numeric_limits<int>::max())
			{
				return -1;
			}

		// if this ID is unused, then it can be used
			if (mapAlertsById.find(i) == mapAlertsById.end())
			{
				return i;
			}
			i++;
		}
	}
}

void CAlert::ProcessAlerts()
{
    {
        LOCK(cs_mapAlerts);
        for (map<uint256, CAlert>::iterator mi = mapAlerts.begin(); mi != mapAlerts.end();)
        {
            const CAlert& alert = (*mi).second;
			if (!alert.IsInEffect())
            {
                printf("expiring alert %d\n", alert.nID);
                uiInterface.NotifyAlertChanged((*mi).first, CT_DELETED);
				mapAlertsById.erase(alert.nID);
                mapAlerts.erase(mi++);
            }
            else
                mi++;
        }
	}
}


bool CAlert::isInfo(int priority)
{
	return (priority <= 300);
}

bool CAlert::isWarning(int priority)
{
	return (priority <= 600);
}

bool CAlert::isCritical(int priority)
{
	return ((priority > 600) && (priority < 999));
}

bool CAlert::isSuperCritical(int priority)
{
	return (priority >= 1000);
}

bool CAlert::isRule(int priority)
{
	return (priority == 999);
}

