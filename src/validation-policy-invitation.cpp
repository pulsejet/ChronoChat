/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "validation-policy-invitation.hpp"
#include "invitation.hpp"

#include "logging.h"

namespace chronochat {

using std::vector;

using ndn::security::v2::CertificateCache;

const shared_ptr<CertificateCache> ValidationPolicyInvitation::DefaultCertificateCache =
  shared_ptr<CertificateCache>();

void
ValidationPolicyInvitation::checkPolicy(const Data& data, const shared_ptr<ValidationState>& state,
                                        const ValidationPolicy::ValidationContinuation& continueValidation)
{
  continueValidation(nullptr, state);
}

void
ValidationPolicyInvitation::checkPolicy(const Interest& interest, const shared_ptr<ValidationState>& state,
                                        const ValidationPolicy::ValidationContinuation& continueValidation)
{
  continueValidation(nullptr, state);
}

} // namespace chronochat
