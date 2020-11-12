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
package org.xwiki.contrib.rights;

import java.util.List;

import org.xwiki.component.annotation.Role;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.security.authorization.ReadableSecurityRule;
import org.xwiki.security.authorization.Right;
import org.xwiki.security.authorization.RuleState;
import org.xwiki.stability.Unstable;

/**
 * @version $Id$
 * @since 1.0
 */
@Role
@Unstable
public interface RightsWriter
{
    /**
     * Creates an empty writable security rule, with state {@link RuleState#ALLOW}.
     * 
     * @return an empty writable security rule, to be filled in by the caller.
     */
    WritableSecurityRule createRule();

    /**
     * Creates a writable security rule for the given subjects and predicates.
     * 
     * @param groups the groups to which the rule applies
     * @param users the users to which the rule applies
     * @param rights the rights concerned by this rule
     * @param ruleState the state (allow or deny) for this rule. If null, {@link RuleState#ALLOW} should be used.
     * @return a writable rule initialized with the passed parameters
     */
    WritableSecurityRule createRule(List<DocumentReference> groups, List<DocumentReference> users, List<Right> rights,
        RuleState ruleState);

    /**
     * Creates a writable security rule that is a copy of the passed readable rule. The copy can be further modified.
     * 
     * @param ruleToCopy the readable rule to turn into a writable rule.
     * @return a writable copy of the passed rule.
     */
    WritableSecurityRule createRule(ReadableSecurityRule ruleToCopy);

    /**
     * Creates a list of writable security rules that are copies of the passed readable rules. The copies can be further
     * modified.
     * 
     * @param rulesToCopy the readable rules to turn into writable rules.
     * @return the list of writable copies of the passed rules.
     */
    List<WritableSecurityRule> createRules(List<ReadableSecurityRule> rulesToCopy);

    /**
     * Saves the passed rules on the given reference. The passed rules replace whatever other rules were already in
     * place on the passed reference, "What you send is what you get". If you need to add to the existing rules of the
     * reference, use the {@link RightsReader} API to read the existing rules, then turn them into writable ones using
     * {@link RightsWriter#createRules(List)}, add a new rule and then persist them using this function.
     * 
     * @param rules the new rules to set for the passed reference. They will replace whatever existing rules are already
     *            there. Writable rules can also be passed, since they are readable as well.
     * @param reference the reference to update rules on. Can be a document or a space or a wiki.
     */
    void saveRules(List<ReadableSecurityRule> rules, EntityReference reference);
}
