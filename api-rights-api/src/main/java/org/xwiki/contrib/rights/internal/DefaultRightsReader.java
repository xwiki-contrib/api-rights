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
import org.xwiki.contrib.rights.WritableSecurityRule;
import org.xwiki.model.EntityType;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.model.reference.WikiReference;
import org.xwiki.security.SecurityReference;
import org.xwiki.security.SecurityReferenceFactory;
import org.xwiki.security.authorization.AuthorizationException;
import org.xwiki.security.authorization.ReadableSecurityRule;
import org.xwiki.security.authorization.RightSet;
import org.xwiki.security.authorization.SecurityEntryReader;
import org.xwiki.security.internal.XWikiBridge;

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

    @Inject
    private XWikiBridge xwikiBridge;

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
    public List<ReadableSecurityRule> getActualRules(EntityReference entityReference)
    {
        // Create a set containing rights that were explicitly encountered going up the parent tree
        // It will be updated based on what is found when looking at parent pages
        RightSet encounteredExplicitRights = new RightSet();
        // The list of all the actual (current + inherited) rules of the page
        List<ReadableSecurityRule> actualRules = new ArrayList<>();

        // Go up the parent tree to get actual rules
        EntityReference entityReferenceToGetRules = entityReference;

        do {
            List<ReadableSecurityRule> inheritedPageRules = this.getRules(entityReferenceToGetRules, false);
            // We need to treat every groups and users on the page before flagging the rights as inherited
            // So we keep track of which rights are explicitly set on this parent page to remove them afterwards
            RightSet toBeAddedExplicitRights = new RightSet();
            // Inspect rules right by right to not miss any explicit right
            inheritedPageRules.forEach(rule -> {
                rule.getRights().forEach(right -> {
                    // If the right was already set explicitly down the document tree, skip
                    if (encounteredExplicitRights.contains(right)) {
                        return;
                    }
                    // Else, this is an actual right for the current page
                    WritableSecurityRule toBeAddedSecurityRule = new WritableSecurityRuleImpl(rule);
                    toBeAddedSecurityRule.setRights(new RightSet(right));
                    actualRules.add(toBeAddedSecurityRule);
                    toBeAddedExplicitRights.add(right);
                });
            });

            // Add every rights we explicitly encountered on the page
            encounteredExplicitRights.addAll(toBeAddedExplicitRights);
            // Go to the parent page
            // Also goes up the main wiki if subwiki
            if (entityReferenceToGetRules.getType() == EntityType.WIKI) {
                WikiReference mainWiki = xwikiBridge.getMainWikiReference();
                entityReferenceToGetRules = entityReferenceToGetRules != mainWiki ? mainWiki : null;
            } else {
                entityReferenceToGetRules = entityReferenceToGetRules.getParent();
            }
        } while (entityReferenceToGetRules != null);



        return actualRules;
    }
}
