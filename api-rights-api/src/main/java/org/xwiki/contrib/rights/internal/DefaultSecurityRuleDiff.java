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

import java.util.Set;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.xwiki.contrib.rights.SecurityRuleDiff;
import org.xwiki.security.authorization.ReadableSecurityRule;

/**
 * Default implementation of {@link SecurityRuleDiff}.
 *
 * @version $Id$
 * @since 2.0
 */
public class DefaultSecurityRuleDiff implements SecurityRuleDiff
{
    private final ReadableSecurityRule previousRule;
    private final ReadableSecurityRule currentRule;
    private final Set<PropertyType> changedProperties;
    private final ChangeType changeType;

    /**
     * Default constructor.
     * @param changeType the type of  change this diff represents.
     * @param previousRule the previous rule or null in case of added rule.
     * @param currentRule the current rule or null in case of deleted rule.
     * @param changedProperties the set of changed properties in case of update, or an empty set.
     */
    public DefaultSecurityRuleDiff(ChangeType changeType, ReadableSecurityRule previousRule,
        ReadableSecurityRule currentRule, Set<PropertyType> changedProperties)
    {
        this.previousRule = previousRule;
        this.currentRule = currentRule;
        this.changedProperties = changedProperties;
        this.changeType = changeType;
    }

    @Override
    public ReadableSecurityRule getPreviousRule()
    {
        return this.previousRule;
    }

    @Override
    public ReadableSecurityRule getCurrentRule()
    {
        return this.currentRule;
    }

    @Override
    public Set<PropertyType> getChangedProperties()
    {
        return this.changedProperties;
    }

    @Override
    public ChangeType getChangeType()
    {
        return changeType;
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o) {
            return true;
        }

        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        DefaultSecurityRuleDiff that = (DefaultSecurityRuleDiff) o;

        return new EqualsBuilder()
            .append(previousRule, that.previousRule)
            .append(currentRule, that.currentRule)
            .append(changedProperties, that.changedProperties)
            .append(changeType, that.changeType).isEquals();
    }

    @Override
    public int hashCode()
    {
        return new HashCodeBuilder(17, 37)
            .append(previousRule)
            .append(currentRule)
            .append(changedProperties)
            .append(changeType).toHashCode();
    }

    @Override
    public String toString()
    {
        return new ToStringBuilder(this)
            .append("previousRule", previousRule)
            .append("currentRule", currentRule)
            .append("changedProperties", changedProperties)
            .append("changeType", changeType)
            .toString();
    }
}
