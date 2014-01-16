/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "sec-policy-chrono-chat-panel.h"
#include <ndn-cpp/security/verifier.hpp>
#include <ndn-cpp/security/signature-sha256-with-rsa.hpp>
// #include <boost/bind.hpp>

#include "logging.h"

using namespace std;
using namespace ndn;
using namespace ndn::ptr_lib;

INIT_LOGGER("SecPolicyChronoChatPanel");

SecPolicyChronoChatPanel::SecPolicyChronoChatPanel(const int & stepLimit)
  : m_stepLimit(stepLimit)
  , m_certificateCache()
{
  m_localPrefixRegex = make_shared<Regex>("^<local><ndn><prefix><><>$");

  m_invitationDataSigningRule = make_shared<SecRuleIdentity>("^<ndn><broadcast><chronos><invitation>([^<chatroom>]*)<chatroom>", 
                                                                "^([^<KEY>]*)<KEY>(<>*)<><ID-CERT><>$", 
                                                                "==", "\\1", "\\1\\2", true);
  
  m_dskRule = make_shared<SecRuleIdentity>("^([^<KEY>]*)<KEY><dsk-.*><ID-CERT><>$", 
                                              "^([^<KEY>]*)<KEY>(<>*)<ksk-.*><ID-CERT>$", 
                                              "==", "\\1", "\\1\\2", true);
  
  m_endorseeRule = make_shared<SecRuleIdentity>("^([^<DNS>]*)<DNS><>*<ENDORSEE><>$", 
                                                   "^([^<KEY>]*)<KEY>(<>*)<ksk-.*><ID-CERT>$", 
                                                   "==", "\\1", "\\1\\2", true);
  
  m_kskRegex = make_shared<Regex>("^([^<KEY>]*)<KEY>(<>*<ksk-.*>)<ID-CERT><>$", "\\1\\2");

  m_keyNameRegex = make_shared<Regex>("^([^<KEY>]*)<KEY>(<>*<ksk-.*>)<ID-CERT>$", "\\1\\2");

  m_signingCertificateRegex = make_shared<Regex>("^<ndn><broadcast><chronos><invitation>([^<chatroom>]*)<chatroom>", "\\1");
}

bool 
SecPolicyChronoChatPanel::skipVerifyAndTrust (const Data & data)
{
  if(m_localPrefixRegex->match(data.getName()))
    return true;
  
  return false;
}

bool
SecPolicyChronoChatPanel::requireVerify (const Data & data)
{
  // if(m_invitationDataRule->matchDataName(data))
  //   return true;
  if(m_kskRegex->match(data.getName()))
     return true;
  if(m_dskRule->matchDataName(data))
    return true;

  if(m_endorseeRule->matchDataName(data))
    return true;


  return false;
}

shared_ptr<ValidationRequest>
SecPolicyChronoChatPanel::checkVerificationPolicy(const shared_ptr<Data>& data, 
                                            int stepCount, 
                                            const OnVerified& onVerified,
                                            const OnVerifyFailed& onVerifyFailed)
{
  if(m_stepLimit == stepCount)
    {
      _LOG_ERROR("Reach the maximum steps of verification!");
      onVerifyFailed(data);
      return shared_ptr<ValidationRequest>();
    }

  try{
    SignatureSha256WithRsa sig(data->getSignature());    
    const Name & keyLocatorName = sig.getKeyLocator().getName();

    if(m_kskRegex->match(data->getName()))
      {
        Name keyName = m_kskRegex->expand();
        map<Name, PublicKey>::iterator it = m_trustAnchors.find(keyName);
        if(m_trustAnchors.end() != it)
          {
            // _LOG_DEBUG("found key!");
            IdentityCertificate identityCertificate(*data);
            if(it->second == identityCertificate.getPublicKeyInfo())
              onVerified(data);
            else
              onVerifyFailed(data);
          }
        else
          onVerifyFailed(data);

        return shared_ptr<ValidationRequest>();
      }

    if(m_dskRule->satisfy(*data))
      {
        m_keyNameRegex->match(keyLocatorName);
        Name keyName = m_keyNameRegex->expand();

        if(m_trustAnchors.end() != m_trustAnchors.find(keyName))
          if(Verifier::verifySignature(*data, sig, m_trustAnchors[keyName]))
            onVerified(data);
          else
            onVerifyFailed(data);
        else
          onVerifyFailed(data);

        return shared_ptr<ValidationRequest>();	
      }

    if(m_endorseeRule->satisfy(*data))
      {
        m_keyNameRegex->match(keyLocatorName);
        Name keyName = m_keyNameRegex->expand();
        if(m_trustAnchors.end() != m_trustAnchors.find(keyName))
          if(Verifier::verifySignature(*data, sig, m_trustAnchors[keyName]))
            onVerified(data);
          else
            onVerifyFailed(data);
        else
          onVerifyFailed(data);

        return shared_ptr<ValidationRequest>();
      }
  }catch(SignatureSha256WithRsa::Error &e){
    _LOG_DEBUG("checkVerificationPolicy: " << e.what());
    onVerifyFailed(data);
    return shared_ptr<ValidationRequest>();
  }catch(KeyLocator::Error &e){
    _LOG_DEBUG("checkVerificationPolicy: " << e.what());
    onVerifyFailed(data);
    return shared_ptr<ValidationRequest>();
  }

  _LOG_DEBUG("Unverified!");

  onVerifyFailed(data);
  return shared_ptr<ValidationRequest>();
}

bool 
SecPolicyChronoChatPanel::checkSigningPolicy(const Name & dataName, const Name & certificateName)
{
  return m_invitationDataSigningRule->satisfy(dataName, certificateName);
}

Name 
SecPolicyChronoChatPanel::inferSigningIdentity(const Name & dataName)
{
  if(m_signingCertificateRegex->match(dataName))
    return m_signingCertificateRegex->expand();
  else
    return Name();
}

void
SecPolicyChronoChatPanel::addTrustAnchor(const EndorseCertificate& selfEndorseCertificate)
{ 
  _LOG_DEBUG("Add Anchor: " << selfEndorseCertificate.getPublicKeyName().toUri());
  m_trustAnchors.insert(pair <Name, PublicKey > (selfEndorseCertificate.getPublicKeyName(), selfEndorseCertificate.getPublicKeyInfo())); 
}

void
SecPolicyChronoChatPanel::removeTrustAnchor(const Name& keyName)
{  
  m_trustAnchors.erase(keyName); 
}

shared_ptr<PublicKey>
SecPolicyChronoChatPanel::getTrustedKey(const Name& inviterCertName)
{
  Name keyLocatorName = inviterCertName.getPrefix(-1);
  _LOG_DEBUG("inviter cert name: " << inviterCertName.toUri());
  m_keyNameRegex->match(keyLocatorName);
  Name keyName = m_keyNameRegex->expand();

  if(m_trustAnchors.end() != m_trustAnchors.find(keyName))
    return make_shared<PublicKey>(m_trustAnchors[keyName]);
  return shared_ptr<PublicKey>();
}