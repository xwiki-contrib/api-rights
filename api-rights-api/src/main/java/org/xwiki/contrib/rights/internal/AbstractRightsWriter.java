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

import org.xwiki.contrib.rights.RightsWriter;
import org.xwiki.contrib.rights.WritableSecurityRule;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.security.authorization.Right;
import org.xwiki.security.authorization.RightSet;
import org.xwiki.security.authorization.RuleState;
import org.xwiki.security.authorization.ReadableSecurityRule;

/**
 * @version $Id$
 */
public abstract class AbstractRightsWriter implements RightsWriter
{
    /**
     * {@inheritDoc}
     *
     * @see org.xwiki.contrib.rights.RightsWriter#createRule()
     */
    @Override
    public WritableSecurityRule createRule()
    {
        return new WritableSecurityRuleImpl();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.xwiki.contrib.rights.RightsWriter#createRule(java.util.List, java.util.List, java.util.List,
     *     org.xwiki.security.authorization.RuleState)
     */
    @Override
    public WritableSecurityRule createRule(List<DocumentReference> groups, List<DocumentReference> users,
        List<Right> rights, RuleState ruleState)
    {
        return new WritableSecurityRuleImpl(groups, users, new RightSet(rights), ruleState);
    }

    /**
     * {@inheritDoc}
     *
     * @see org.xwiki.contrib.rights.RightsWriter#createRule(ReadableSecurityRule)
     */
    @Override
    public WritableSecurityRule createRule(ReadableSecurityRule ruleToCopy)
    {
        return new WritableSecurityRuleImpl(ruleToCopy.getGroups(), ruleToCopy.getUsers(), ruleToCopy.getRights(),
            ruleToCopy.getState());
    }

    /**
     * {@inheritDoc}
     *
     * @see org.xwiki.contrib.rights.RightsWriter#createRules(java.util.List)
     */
    @Override
    public List<WritableSecurityRule> createRules(List<ReadableSecurityRule> rulesToCopy)
    {
        List<WritableSecurityRule> writableRules = new ArrayList<>();
        for (ReadableSecurityRule rule : rulesToCopy) {
            writableRules.add(new WritableSecurityRuleImpl(rule.getGroups(), rule.getUsers(), rule.getRights(),
                rule.getState()));
        }
        return writableRules;
    }
}
