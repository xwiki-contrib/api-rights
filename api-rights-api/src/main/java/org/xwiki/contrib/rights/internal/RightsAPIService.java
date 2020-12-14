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
import java.util.stream.Collectors;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.rights.RightsReader;
import org.xwiki.contrib.rights.RightsWriter;
import org.xwiki.contrib.rights.WritableSecurityRule;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.script.service.ScriptService;
import org.xwiki.security.authorization.AuthorizationManager;
import org.xwiki.security.authorization.ReadableSecurityRule;
import org.xwiki.security.authorization.Right;
import org.xwiki.security.authorization.RuleState;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;

/**
 * @version $Id: $
 */
@Component
@Named("rights")
@Singleton
public class RightsAPIService implements ScriptService
{
    private static final String ERROR_MESSAGE = "message";

    @Inject
    private Provider<XWikiContext> xcontextProvider;

    @Inject
    private RightsReader rightsReader;

    @Inject
    private RightsWriter rightsWriter;

    @Inject
    private AuthorizationManager authorization;

    @Inject
    private DocumentReferenceResolver<String> documentReferenceResolver;

    // TODO: inject a logger & log the operations.

    /**
     * @param ref
     * @return the list with the rules that are actually applying for @ref.
     */
    public List<ReadableSecurityRule> getActualRules(EntityReference ref)
    {
        return rightsReader.getActualRules(ref);
    }

    /**
     * @param ref the reference for which the rules will be retrieved
     * @param withImplied whether implied rules should also be returned or only persisted rules
     * @return the list of security rules that apply to the passed entity
     */
    public List<ReadableSecurityRule> getRules(EntityReference ref, Boolean withImplied)
    {
        return rightsReader.getRules(ref, withImplied);
    }

    /**
     * Saves the passed rules.
     *
     * @param rules the rules to save.
     * @param reference the reference to save rules on. In order to actually save the rules, the reference must be a
     *     Document, Space or a Wiki.
     * @return whether the save was successful or not.
     */
    public boolean saveRules(List<ReadableSecurityRule> rules, EntityReference reference)
    {
        if (authorization.hasAccess(Right.EDIT, xcontextProvider.get().getUserReference(), reference)) {
            try {
                rightsWriter.saveRules(rules, reference);
                return true;
            } catch (UnsupportedOperationException | IllegalArgumentException | XWikiException e) {
                xcontextProvider.get().put(ERROR_MESSAGE, e.toString());
            }
        }
        return false;
    }

    /**
     * Converts a ReadableSecurityRule to a WritableSecurityRule.
     *
     * @param readableSecurityRule a rule to be converted in a modifiable (writable) one
     * @return a writable rule, with the same properties as the rule passed as argument
     */
    public WritableSecurityRule createWritableRule(ReadableSecurityRule readableSecurityRule)
    {
        if (null == readableSecurityRule) {
            xcontextProvider.get().put(ERROR_MESSAGE, "The passed securityRule is null.");
            return null;
        }
        return new WritableSecurityRuleImpl(readableSecurityRule.getGroups(),
            readableSecurityRule.getUsers(), readableSecurityRule.getRights(), readableSecurityRule.getState());
    }

    /**
     * @param groups
     * @param users
     * @param levels
     * @param allowOrNot
     * @return a writable/modifiable rule, according to the given parameters
     */
    public WritableSecurityRule createWritableRule(List<String> groups, List<String> users,
        List<String> levels, String allowOrNot)
    {
        WritableSecurityRule writableSecurityRule = new WritableSecurityRuleImpl();
        if (null != groups) {
            writableSecurityRule.setGroups(groups.stream()
                .map(group -> documentReferenceResolver.resolve(group))
                .collect(Collectors.toList())
            );
        }

        if (null != users) {
            writableSecurityRule.setUsers(users.stream()
                .map(user -> documentReferenceResolver.resolve(user))
                .collect(Collectors.toList())
            );
        }

        if (null != levels) {
            writableSecurityRule.setRights(levels.stream()
                .map(Right::toRight)
                .collect(Collectors.toList()));
        }

        if ("ALLOW".equals(allowOrNot.toUpperCase())) {
            writableSecurityRule.setState(RuleState.ALLOW);
        } else if ("DENY".equals(allowOrNot.toUpperCase())) {
            writableSecurityRule.setState(RuleState.DENY);
        }
        return writableSecurityRule;
    }
}
