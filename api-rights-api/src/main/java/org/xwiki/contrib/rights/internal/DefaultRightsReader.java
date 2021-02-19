/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.xwiki.contrib.rights.internal;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.rights.RightsReader;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.security.SecurityReference;
import org.xwiki.security.SecurityReferenceFactory;
import org.xwiki.security.authorization.AuthorizationException;
import org.xwiki.security.authorization.SecurityEntryReader;
import org.xwiki.security.authorization.ReadableSecurityRule;

/**
 * @version $Id$
 */
@Component
@Singleton
public class DefaultRightsReader implements RightsReader
{
    @Inject
    @Named("api-rights")
    private SecurityEntryReader securityEntryReader;

    @Inject
    private SecurityReferenceFactory securityReferenceFactory;

    /**
     * {@inheritDoc}
     *
     * @see org.xwiki.contrib.rights.RightsReader#getRules(org.xwiki.model.reference.EntityReference, java.lang.Boolean)
     */
    @Override
    public List<ReadableSecurityRule> getRules(EntityReference ref, Boolean withImplied)
    {
        // TODO: see how we should handle SecurityEntryReaderExtra from DefaultSecurityEntryReader#read(ref).
        if (withImplied) {
            SecurityReference reference = securityReferenceFactory.newEntityReference(ref);
            try {
                return securityEntryReader.read(reference).getRules().stream()
                    .filter(k -> k instanceof ReadableSecurityRule)
                    .map(k -> (ReadableSecurityRule) k)
                    .collect(Collectors.toList());
            } catch (AuthorizationException e) {
                e.printStackTrace();
            }
        } else {
            return getPersistedRules(ref);
        }
        return new ArrayList<>();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.xwiki.contrib.rights.RightsReader#getPersistedRules(org.xwiki.model.reference.EntityReference)
     */
    @Override
    public List<ReadableSecurityRule> getPersistedRules(EntityReference ref)
    {
        SecurityReference reference = securityReferenceFactory.newEntityReference(ref);
        try {
            return securityEntryReader.read(reference).getRules().stream()
                .filter(k -> k instanceof ReadableSecurityRule)
                .filter(k -> ((ReadableSecurityRule) k).isPersisted())
                .map(k -> (ReadableSecurityRule) k)
                .collect(Collectors.toList());
        } catch (AuthorizationException e) {
            e.printStackTrace();
        }
        return new ArrayList<>();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.xwiki.contrib.rights.RightsReader#getActualRules(org.xwiki.model.reference.EntityReference)
     */
    @Override
    public List<ReadableSecurityRule> getActualRules(EntityReference ref)
    {
        // TODO Auto-generated method stub
        return null;
    }
}
