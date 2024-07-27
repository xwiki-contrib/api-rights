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
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.inject.Inject;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.apache.commons.lang3.tuple.MutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.lang3.StringUtils;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.rights.SecurityRuleAbacus;
import org.xwiki.contrib.rights.SecurityRuleDiff;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.EntityReferenceSerializer;
import org.xwiki.security.authorization.ReadableSecurityRule;
import org.xwiki.security.authorization.RightSet;
import org.xwiki.security.authorization.RuleState;
import org.xwiki.security.internal.XWikiConstants;

import com.xpn.xwiki.XWikiContext;

/**
 * Default implementation of the {@link org.xwiki.contrib.rights.SecurityRuleAbacus}.
 *
 * @version $Id$
 */
@Component
@Singleton
public class DefaultSecurityRuleAbacus implements SecurityRuleAbacus
{
    @Inject
    private EntityReferenceSerializer<String> entityReferenceSerializer;

    @Inject
    private Provider<XWikiContext> xcontextProvider;

    /**
     * {@inheritDoc}
     */
    @Override
    public List<ReadableSecurityRule> normalizeRulesBySubject(List<ReadableSecurityRule> rules)
    {
        Map<String, ReadableSecurityRule> normalizedRulesMap = new HashMap<>();

        // Inspect rules right by right to not miss any explicit right
        rules.forEach(rule -> {
            List<DocumentReference> groups = rule.getGroups();
            if (groups == null) {
                groups = Collections.emptyList();
            }
            groups.forEach(group -> {
                String ruleMapKey = entityReferenceSerializer.serialize(group) + rule.getState().name();
                if (!normalizedRulesMap.containsKey(ruleMapKey)) {
                    // First time we encounter the group, add a new rule in the hashmap
                    normalizedRulesMap.put(ruleMapKey, new WritableSecurityRuleImpl(
                        Collections.singletonList(group),
                        Collections.emptyList(),
                        new RightSet(rule.getRights()),
                        rule.getState()
                    ));
                } else {
                    // The same group already exists in the hashmap, so only update rights
                    ReadableSecurityRule groupRule = normalizedRulesMap.get(ruleMapKey);
                    groupRule.getRights().addAll(rule.getRights());
                }
            });
            List<DocumentReference> users = rule.getUsers();
            if (users == null) {
                users = Collections.emptyList();
            }
            users.forEach(user -> {
                String ruleMapKey = entityReferenceSerializer.serialize(user) + rule.getState().name();
                if (!normalizedRulesMap.containsKey(ruleMapKey)) {
                    // First time we encounter the user, add a new rule in the hashmap
                    normalizedRulesMap.put(ruleMapKey, new WritableSecurityRuleImpl(
                        Collections.emptyList(),
                        Collections.singletonList(user),
                        new RightSet(rule.getRights()),
                        rule.getState()
                    ));
                } else {
                    // The same user already exists in the hashmap, so only update rights
                    ReadableSecurityRule userRule = normalizedRulesMap.get(ruleMapKey);
                    userRule.getRights().addAll(rule.getRights());
                }
            });
        });

        return new ArrayList<ReadableSecurityRule>(normalizedRulesMap.values());
    }

    private boolean isSameRuleUpdate(ReadableSecurityRule previousRule, ReadableSecurityRule currentRule)
    {
        boolean previousSubjectIsGroup = previousRule.getUsers().isEmpty();
        boolean currentSubjectIsGroup = currentRule.getUsers().isEmpty();
        if (previousSubjectIsGroup == currentSubjectIsGroup && previousRule.getState() == currentRule.getState()) {
            if (previousSubjectIsGroup) {
                return previousRule.getGroups().equals(currentRule.getGroups());
            } else {
                return previousRule.getUsers().equals(currentRule.getUsers());
            }
        }
        return false;
    }

    @Override
    public List<SecurityRuleDiff> computeRuleDiff(List<ReadableSecurityRule> previousRules,
        List<ReadableSecurityRule> currentRules)
    {
        List<ReadableSecurityRule> normalizedPreviousRules = this.normalizeRulesBySubject(previousRules);
        List<ReadableSecurityRule> normalizedCurrentRules = this.normalizeRulesBySubject(currentRules);

        List<SecurityRuleDiff> result = new ArrayList<>();

        List<ReadableSecurityRule> intersectionRules =
            normalizedCurrentRules.stream().filter(normalizedPreviousRules::contains).collect(Collectors.toList());

        normalizedPreviousRules.removeAll(intersectionRules);
        normalizedCurrentRules.removeAll(intersectionRules);

        normalizedPreviousRules.sort(ReadableSecurityRuleComparator.INSTANCE);
        normalizedCurrentRules.sort(ReadableSecurityRuleComparator.INSTANCE);

        for (ReadableSecurityRule normalizedPreviousRule : normalizedPreviousRules) {
            boolean updated = false;
            for (ReadableSecurityRule currentRule : normalizedCurrentRules) {
                if (isSameRuleUpdate(normalizedPreviousRule, currentRule)) {
                    result.add(new DefaultSecurityRuleDiff(SecurityRuleDiff.ChangeType.RULE_UPDATED,
                        normalizedPreviousRule, currentRule,
                        Collections.singleton(SecurityRuleDiff.PropertyType.RIGHTS)));
                    normalizedCurrentRules.remove(currentRule);
                    updated = true;
                    break;
                }
            }
            if (!updated) {
                result.add(new DefaultSecurityRuleDiff(SecurityRuleDiff.ChangeType.RULE_DELETED,
                    normalizedPreviousRule, null, Collections.emptySet()));
            }
        }

        for (ReadableSecurityRule normalizedCurrentRule : normalizedCurrentRules) {
            result.add(new DefaultSecurityRuleDiff(SecurityRuleDiff.ChangeType.RULE_ADDED,
                null, normalizedCurrentRule, Collections.emptySet()));
        }

        return result;
    }

    private static final class ReadableSecurityRuleComparator implements Comparator<ReadableSecurityRule>
    {
        private static final ReadableSecurityRuleComparator INSTANCE = new ReadableSecurityRuleComparator();

        private ReadableSecurityRuleComparator()
        {
        }

        @Override
        public int compare(ReadableSecurityRule rule1, ReadableSecurityRule rule2)
        {
            if (rule1.equals(rule2)) {
                return 0;
            } else if (!rule1.getState().equals(rule2.getState())) {
                return rule1.getState().compareTo(rule2.getState());
            } else if (!rule1.getUsers().equals(rule2.getUsers())) {
                return StringUtils.join(rule1.getUsers()).compareTo(StringUtils.join(rule2.getUsers()));
            } else if (!rule1.getGroups().equals(rule2.getGroups())) {
                return StringUtils.join(rule1.getGroups()).compareTo(StringUtils.join(rule2.getGroups()));
            } else {
                return StringUtils.join(rule1.getRights()).compareTo(StringUtils.join(rule2.getRights()));
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<ReadableSecurityRule> getUserRulesNormalized(List<ReadableSecurityRule> rules)
    {
        List<ReadableSecurityRule> normalizeRulesBySubject = normalizeRulesBySubject(rules);

        return normalizeRulesBySubject.stream().filter(rule -> !rule.getUsers().isEmpty()).collect(Collectors.toList());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<ReadableSecurityRule> getGroupRulesNormalized(List<ReadableSecurityRule> rules)
    {
        List<ReadableSecurityRule> normalizeRulesBySubject = normalizeRulesBySubject(rules);

        return normalizeRulesBySubject.stream().filter(rule -> !rule.getGroups().isEmpty())
            .collect(Collectors.toList());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Map<DocumentReference, Pair<ReadableSecurityRule, ReadableSecurityRule>> organizeRulesBySubjectAndState(
        List<ReadableSecurityRule> rules)
    {
        Map<DocumentReference, Pair<ReadableSecurityRule, ReadableSecurityRule>> result = new HashMap<>();

        List<ReadableSecurityRule> normalizeRulesBySubject = normalizeRulesBySubject(rules);

        normalizeRulesBySubject.forEach(rule -> {
            DocumentReference subject = null;

            if (!rule.getUsers().isEmpty()) {
                subject = fixDocumentReferenceIfGuestUser(rule.getUsers().get(0));
            } else if (!rule.getGroups().isEmpty()) {
                subject = rule.getGroups().get(0);
            }

            if (subject != null) {
                if (!result.containsKey(subject)) {
                    result.put(subject, new MutablePair());
                }

                if (RuleState.ALLOW.name().equals(rule.getState().name())) {
                    ((MutablePair) result.get(subject)).setLeft(rule);
                } else {
                    ((MutablePair) result.get(subject)).setRight(rule);
                }
            }
        });

        return result;
    }

    /*
     * Get the Guest user DocumentReference as it is stored in the Database (using a user named XWikiGuest) because in
     * rule objects Guest user reference is set to null.
     * @param userDocumentReference a user document reference
     * @return userDocumentReference as it is if userDocumentReference is not null, otherwise return the guest user
     * reference (XWiki.XWikiGuest).
     */
    private DocumentReference fixDocumentReferenceIfGuestUser(DocumentReference userDocumentReference)
    {
        if (userDocumentReference == null) {
            return new DocumentReference(xcontextProvider.get().getMainXWiki(), XWikiConstants.XWIKI_SPACE,
                XWikiConstants.GUEST_USER);
        }

        return userDocumentReference;
    }
}
