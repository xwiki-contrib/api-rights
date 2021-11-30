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
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.rights.RightsReader;
import org.xwiki.contrib.rights.WritableSecurityRule;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.security.SecurityReference;
import org.xwiki.security.SecurityReferenceFactory;
import org.xwiki.security.authorization.AuthorizationException;
import org.xwiki.security.authorization.ReadableSecurityRule;
import org.xwiki.security.authorization.Right;
import org.xwiki.security.authorization.RightSet;
import org.xwiki.security.authorization.RuleState;
import org.xwiki.security.authorization.SecurityEntryReader;
import org.xwiki.security.authorization.SecurityRule;
import org.xwiki.security.authorization.SecurityRuleEntry;

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
     * @see org.xwiki.contrib.rights.RightsReader#getRules(org.xwiki.model.reference.EntityReference, boolean)
     */
    @Override
    public List<ReadableSecurityRule> getRules(EntityReference entityReference, boolean withImplied)
        throws AuthorizationException
    {
        // TODO: see how we should handle SecurityEntryReaderExtra from DefaultSecurityEntryReader#read(ref).
        SecurityReference securityReference = securityReferenceFactory.newEntityReference(entityReference);
        List<ReadableSecurityRule> rules = new ArrayList<>();
        SecurityRuleEntry securityRuleEntry = securityEntryReader.read(securityReference);
        Collection<SecurityRule> securityRules = securityRuleEntry.getRules();
        securityRules.forEach(rule -> {
            if (!(rule instanceof ReadableSecurityRule)) {
                return;
            }
            if (!withImplied && !((ReadableSecurityRule) rule).isPersisted()) {
                return;
            }
            rules.add((ReadableSecurityRule) rule);
        });
        return rules;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.xwiki.contrib.rights.RightsReader#getActualRules(org.xwiki.model.reference.EntityReference)
     */
    @Override
    public List<ReadableSecurityRule> getActualRules(EntityReference entityReference)
        throws AuthorizationException
    {
        // Create a set containing allowed rights that were explicitly encountered going up the parent tree
        // It will be updated based on what is found when looking at parent pages
        // It only contains rights for which inheritanceOverridePolicy flag is true
        RightSet encounteredAllowRights = new RightSet();

        // Create a set containing denied rights and associated exact subjects of the rules: if a higher rule is an
        // allow but matches a deny rule for same subject, it will be ignored.
        Map<Right, Set<DocumentReference>> encounteredDenyRights = new HashMap<>();
        // The list of all the actual (current + inherited) rules of the page
        List<ReadableSecurityRule> actualRules = new ArrayList<>();

        // Go up the parent tree to get actual rules
        SecurityReference securityReference = securityReferenceFactory.newEntityReference(entityReference);

        do {
            List<ReadableSecurityRule> inheritedPageRules = this.getRules(securityReference, false);
            // We need to treat every groups and users on the page before flagging the rights as inherited
            // So we keep track of which rights are explicitly set on this parent page to remove them afterwards
            RightSet toBeAddedExplicitAllowRights = new RightSet();

            // Inspect rules right by right to not miss any explicit right
            for (ReadableSecurityRule rule : inheritedPageRules) {
                for (Right right : rule.getRights()) {
                    // If the right was already set explicitly with an Allow rule down the document tree, skip
                    // Note that we're doing that because Allow in XWiki automatically set a whitelist: all users
                    // that are not part of the subject will be denied the right, so we can safely ignore the rules
                    // above.
                    if (encounteredAllowRights.contains(right)) {
                        continue;
                    }
                    // Else, this is an actual right for the current page
                    WritableSecurityRule toBeAddedSecurityRule = new WritableSecurityRuleImpl(rule);
                    toBeAddedSecurityRule.setRights(new RightSet(right));
                    actualRules.add(toBeAddedSecurityRule);
                    // If right override higher level, and is allow, add it to be ignored for parent rules
                    if (right.getInheritanceOverridePolicy() && rule.getState() == RuleState.ALLOW) {
                        toBeAddedExplicitAllowRights.add(right);
                    }
                }
            }

            // Add rights we explicitly encountered on the page to be ignored in parent rules
            encounteredAllowRights.addAll(toBeAddedExplicitAllowRights);

            // Go to the parent security reference (parent space or main wiki)
            securityReference = securityReference.getParentSecurityReference();
        } while (securityReference != null);

        return actualRules;
    }
}
