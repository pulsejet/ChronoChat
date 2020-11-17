/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "validator-panel.hpp"

#include "logging.h"

namespace chronochat {

using std::vector;

using ndn::security::v2::CertificateCache;
using ndn::security::v2::Certificate;

const shared_ptr<CertificateCache> ValidatorPanel::DEFAULT_CERT_CACHE =
  shared_ptr<CertificateCache>();

ValidatorPanel::ValidatorPanel(int stepLimit,
                               const shared_ptr<CertificateCache> certificateCache)
  // : m_stepLimit(stepLimit)
  : m_certificateCache(certificateCache)
{
}

void
ValidatorPanel::removeTrustAnchor(const Name& keyName)
{
  m_trustAnchors.erase(keyName);
}

void
ValidatorPanel::checkPolicy (const Data& data,
                             int stepCount,
                             const OnDataValidated& onValidated)
{
  onValidated(data.shared_from_this());
}

} // namespace chronochat
