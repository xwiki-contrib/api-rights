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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.inject.Inject;
import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.rights.SecurityRuleAbacus;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.EntityReferenceSerializer;
import org.xwiki.security.authorization.ReadableSecurityRule;
import org.xwiki.security.authorization.RightSet;

/**
 * {@inheritDoc}
 *
 * @version $Id$
 */
@Component
@Singleton
public class DefaultSecurityRuleAbacus implements SecurityRuleAbacus
{
    @Inject
    private EntityReferenceSerializer<String> entityReferenceSerializer;

    /**
     * {@inheritDoc}
     */
    @Override
    public List<ReadableSecurityRule> normalizeRules(List<ReadableSecurityRule> rules)
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
}
