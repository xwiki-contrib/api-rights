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
import java.util.Map;

import org.apache.commons.lang3.tuple.Pair;
import org.xwiki.component.annotation.Role;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.security.authorization.ReadableSecurityRule;
import org.xwiki.stability.Unstable;

/**
 * The security abacus provides functions in order to perform various operations on security rules.
 *
 * @version $Id$
 * @since 1.1
 */
@Role
public interface SecurityRuleAbacus
{
    /**
     * Normalize given rules so that it is easier to use. The normalization will ensure that:
     * <ul>
     * <li>there is only one [subject, state] per rule</li>
     * <li>there is only one rule per [subject, state]</li>
     * </ul>
     *
     * @param rules A list of rules
     * @return The normalized list of rules
     */
    List<ReadableSecurityRule> normalizeRulesBySubject(List<ReadableSecurityRule> rules);

    /**
     * Compute a diff between the previous rules and the current ones.
     * This diff is computed by first normalizing the rules (see {@link #normalizeRulesBySubject(List)} and then by
     * comparing them by couple (subject, state).
     * Then this diff implementation will never return any {@link SecurityRuleDiff} containing a
     * {@link org.xwiki.contrib.rights.SecurityRuleDiff.PropertyType} other than
     * {@link org.xwiki.contrib.rights.SecurityRuleDiff.PropertyType#RIGHTS} in case of
     * {@link org.xwiki.contrib.rights.SecurityRuleDiff.ChangeType#RULE_UPDATED}. For all other kind of changes, the
     * diff will compute added and deleted changes. Also note that the returned {@link SecurityRuleDiff} will contain
     * always the normalized rules.
     *
     * @param previousRules the previous rules to be compared
     * @param currentRules the current rules to be compared
     * @return a list of {@link SecurityRuleDiff} showing the differences between the given rules, after normalization.
     * @since 2.0
     */
    @Unstable
    List<SecurityRuleDiff> computeRuleDiff(List<ReadableSecurityRule> previousRules,
        List<ReadableSecurityRule> currentRules);

    /**
     * Extract rules whose subject is a user from a set of rules. Returned rules are normalized, check the
     * {@link #normalizeRulesBySubject(List) normalizeRulesBySubject(List&lt;ReadableSecurityRule&gt;)} method.
     *
     * @param rules A list of rules
     * @return The list of user rules
     */
    List<ReadableSecurityRule> getUserRulesNormalized(List<ReadableSecurityRule> rules);

    /**
     * Extract rules whose subject is a group from a set of rules. Returned rules are normalized, check the
     * {@link #normalizeRulesBySubject(List) normalizeRulesBySubject(List&lt;ReadableSecurityRule&gt;)} method.
     *
     * @param rules A list of rules
     * @return The list of group rules
     */
    List<ReadableSecurityRule> getGroupRulesNormalized(List<ReadableSecurityRule> rules);

    /**
     * Organize a set of rules based on subject reference and rule state (Allow/Deny).
     *
     * @param rules A list of rules
     * @return A map where the key is a subject (user/group) DocumentReference and the value is a Pair of rules where
     *         the left rule contains allowed rights and the right rule contains denied rights.
     * @since 2.2
     */
    @Unstable
    Map<DocumentReference, Pair<ReadableSecurityRule, ReadableSecurityRule>> organizeRulesBySubjectAndState(
        List<ReadableSecurityRule> rules);
}
