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

import java.util.List;

import org.xwiki.model.reference.DocumentReference;
import org.xwiki.security.authorization.ReadableSecurityRule;
import org.xwiki.security.authorization.Right;
import org.xwiki.security.authorization.RightSet;
import org.xwiki.security.authorization.RuleState;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Base class for DefaultRightsUIHelper tests.
 *
 * @version $Id$
 */
public class AbstractRightsTest
{
    /**
     * Helper function to assert that the list of actual rules "actualRules" contains a single rule for the passed
     * expected subject (which can be either a user or a group subject, but _only_ one of the 2), and that the rule in
     * question matches the passed rights and state. <br> The assertions will fail if either of the following arrive:
     * <ul>
     * <li>the actualRules doesn't contain any rule for the passed [subject, state], of the passed type</li>
     * <li>the actualRules contains more than one rule for the passed [subject, state], of the passed type</li>
     * <li>the actualRules contains a rule for the passed subject, of the passed type but this subject is not the only
     * subject of this rule</li>
     * <li>the rule found in actualRules that matches all the constraints above does not specify the passed rights or
     * the passed state</li>
     * </ul>
     * A typical correct test for a collection of subject normalized rules has the following structure, in order to
     * ensure a complete check of actualRules:
     * <ul>
     * <li>check that the size of the actualRules list is the expected one, for example x rules;</li>
     * <li>call x times this helper function, to check the state of the x different expected subjects.</li>
     * </ul>
     *
     * @param actualRules the list of rules to search a rule in
     * @param expectedSubject the subject we're searching for
     * @param subjectIsGroup the type of subject we're searching for
     * @param expectedRights the expected rights of the rule
     * @param expectedRuleState the expected state of the rule
     */
    protected void assertContainsRule(List<ReadableSecurityRule> actualRules, DocumentReference expectedSubject,
        boolean subjectIsGroup, List<Right> expectedRights, RuleState expectedRuleState)
    {
        ReadableSecurityRule foundRule = null;
        for (ReadableSecurityRule r : actualRules) {
            boolean matches = false;
            List<DocumentReference> subjectsList = subjectIsGroup ? r.getGroups() : r.getUsers();
            if (subjectsList != null && subjectsList.size() == 1 && subjectsList.contains(expectedSubject)
                && expectedRuleState == r.getState())
            {
                // only match if the other subjects are null
                List<DocumentReference> otherSubjects = !subjectIsGroup ? r.getGroups() : r.getUsers();
                if (otherSubjects == null || otherSubjects.isEmpty()) {
                    matches = true;
                }
            }
            // if current rule matches the expected subject, let's assert the rest
            if (matches) {
                // check that no rule was found to match before
                assertNull(foundRule, "A second rule matching the subject " + expectedSubject + " was found");
                // and store the found rule as the rule to find. Continue checking to the end, to make sure this is the
                // only rule matching the subject, as expected.
                foundRule = r;
            }
        }
        // check that a rule was found
        assertNotNull(foundRule,
            "No rule only for subject " + expectedSubject + " and state " + expectedRuleState.name() + " was found");
        // check the rights of the found rule and the state
        RightSet foundRuleRights = foundRule.getRights();
        // there is probably a better way to make this sets comparison
        assertTrue(expectedRights.containsAll(foundRuleRights) && foundRuleRights.containsAll(expectedRights),
            "Rule found for subject " + expectedSubject + " does not contain the expected rights " + expectedRights);
    }
}
