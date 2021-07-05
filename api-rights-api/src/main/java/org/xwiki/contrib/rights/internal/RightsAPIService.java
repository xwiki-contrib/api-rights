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

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.component.manager.ComponentLookupException;
import org.xwiki.contrib.rights.RightsReader;
import org.xwiki.contrib.rights.RightsWriter;
import org.xwiki.contrib.rights.SecurityRuleAbacus;
import org.xwiki.contrib.rights.WritableSecurityRule;
import org.xwiki.model.EntityType;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.model.reference.SpaceReference;
import org.xwiki.model.reference.WikiReference;
import org.xwiki.script.service.ScriptService;
import org.xwiki.security.authorization.AuthorizationManager;
import org.xwiki.security.authorization.ReadableSecurityRule;
import org.xwiki.security.authorization.Right;
import org.xwiki.security.authorization.RuleState;
import org.xwiki.stability.Unstable;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;

/**
 * @version $Id: $
 * @since 1.0-SNAPSHOT
 */
@Component
@Named("security.rights")
@Singleton
@Unstable
public class RightsAPIService implements ScriptService
{
    private static final String ERROR_MESSAGE = "message";

    private static final String XWIKI_SPACE = "XWiki";

    private static final String XWIKI_WEB_PREFERENCES = "WebPreferences";

    private static final String XWIKI_PREFERENCES = "XWikiPreferences";

    @Inject
    private Provider<XWikiContext> xcontextProvider;

    @Inject
    private RightsReader rightsReader;

    @Inject
    private RightsWriter rightsWriter;

    @Inject
    private SecurityRuleAbacus securityRuleAbacus;

    @Inject
    private AuthorizationManager authorization;

    @Inject
    private DocumentReferenceResolver<String> documentReferenceResolver;

    @Inject
    private Logger logger;

    /**
     * @param ref the {@link EntityReference} for which the rules will be retrieved. Depending on the {@link
     *     org.xwiki.model.EntityType} of the <code>ref</code>, the rules will be read from the wiki, space or
     *     document.
     * @return the list of rules that are actually applying for <code>ref</code>.
     */
    public List<ReadableSecurityRule> getActualRules(EntityReference ref)
    {
        return rightsReader.getActualRules(ref);
    }

    /**
     * @param ref the {@link EntityReference} for which the rules will be retrieved. Depending on the {@link
     *     org.xwiki.model.EntityType} of the <code>ref</code>, the rules will be read from the wiki, space or
     *     document.
     * @param withImplied whether implied rules should also be returned or only persisted rules
     * @return the list of security rules that apply to the passed entity
     */
    public List<ReadableSecurityRule> getRules(EntityReference ref, Boolean withImplied)
    {
        return rightsReader.getRules(ref, withImplied);
    }

    /**
     * Saves the passed rules, with the default recycling strategy.
     *
     * @param rules the rules to save.
     * @param reference the reference to save rules on. In order to actually save the rules, the reference must be a
     *     Document, Space or a Wiki.
     * @return whether the save was successful or not.
     */
    public boolean saveRules(List<ReadableSecurityRule> rules, EntityReference reference)
    {
        return saveRules(rules, reference, null);
    }

    /**
     * Saves the passed rules, accordingly to the gives <code>strategy</code>.
     *
     * @param rules the rules to save
     * @param reference the reference to save rules on. In order to actually save the rules, the reference must be a
     *     {@link org.xwiki.model.EntityType#DOCUMENT}, {@link org.xwiki.model.EntityType#SPACE} or {@link
     *     org.xwiki.model.EntityType#WIKI}
     * @param strategyName a strategy for persisting the objects. It needs to be the name of an implementation of
     *     RulesObjectWriter. TODO: there should be a link to the interface, but needs to be fixed
     * @return whether the save was successful or not.
     */
    public boolean saveRules(List<ReadableSecurityRule> rules, EntityReference reference, String strategyName)
    {
        if (userHasAccessInOrderToChangeRights(xcontextProvider.get().getUserReference(), reference)) {
            try {
                if (null != strategyName && !StringUtils.isBlank(strategyName)) {
                    rightsWriter.saveRules(rules, reference, strategyName);
                } else {
                    rightsWriter.saveRules(rules, reference);
                }
                return true;
            } catch (UnsupportedOperationException | IllegalArgumentException | XWikiException
                | ComponentLookupException e) {
                xcontextProvider.get().put(ERROR_MESSAGE, e.toString());
                logger.error(e.toString(), e);
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
        return new WritableSecurityRuleImpl(readableSecurityRule);
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

        if ("ALLOW".equalsIgnoreCase(allowOrNot)) {
            writableSecurityRule.setState(RuleState.ALLOW);
        } else if ("DENY".equalsIgnoreCase(allowOrNot)) {
            writableSecurityRule.setState(RuleState.DENY);
        }
        return writableSecurityRule;
    }

    /**
     * Normalize a list of security rules to a canonical form, so that there is one and only one [user, state] per rule.
     *
     * @param rules The rules to normalize
     * @return The normalized rules
     */
    public List<ReadableSecurityRule> normalizeRulesBySubject(List<ReadableSecurityRule> rules)
    {
        return this.securityRuleAbacus.normalizeRulesBySubject(rules);
    }

    private boolean userHasAccessInOrderToChangeRights(DocumentReference user, EntityReference targetEntity)
    {
        DocumentReference doc;
        if (EntityType.DOCUMENT != targetEntity.getType()) {
            switch (targetEntity.getType()) {
                case WIKI:
                    doc = new DocumentReference(XWIKI_PREFERENCES,
                        new SpaceReference(XWIKI_SPACE, new WikiReference(targetEntity)));
                    break;
                case SPACE:
                    doc = new DocumentReference(XWIKI_WEB_PREFERENCES, new SpaceReference(targetEntity));
                    break;
                default:
                    String couldNotVerifyAccessForGivenReference = "Could not determine if the user has access on"
                        + " the given documentReference";
                    xcontextProvider.get().put(ERROR_MESSAGE, couldNotVerifyAccessForGivenReference);
                    logger.error(couldNotVerifyAccessForGivenReference);
                    return false;
            }
        } else {
            doc = new DocumentReference(targetEntity);
        }
        return authorization.hasAccess(Right.EDIT, user, doc);
    }
}
