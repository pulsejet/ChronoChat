/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "validator-invitation.hpp"
#include "invitation.hpp"

#include "logging.h"

namespace chronochat {

using std::vector;

using ndn::security::v2::CertificateCache;

const shared_ptr<CertificateCache> ValidatorInvitation::DefaultCertificateCache =
  shared_ptr<CertificateCache>();

ValidatorInvitation::ValidatorInvitation()
{
}

void
ValidatorInvitation::addTrustAnchor(const Name& keyName, const ndn::Buffer& key)
{
  m_trustAnchors[keyName] = key;
}

void
ValidatorInvitation::removeTrustAnchor(const Name& keyName)
{
  m_trustAnchors.erase(keyName);
}

void
ValidatorInvitation::cleanTrustAnchor()
{
  m_trustAnchors.clear();
}

void
ValidatorInvitation::checkPolicy (const Data& data,
                                  int stepCount,
                                  const OnDataValidated& onValidated)
{
  onValidated(data.shared_from_this());
}

void
ValidatorInvitation::checkPolicy (const Interest& interest,
                                  int stepCount,
                                  const OnInterestValidated& onValidated)
{
  return onValidated(interest.shared_from_this());
}

} // namespace chronochat
