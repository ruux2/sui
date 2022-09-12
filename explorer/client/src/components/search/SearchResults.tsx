// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { Fragment } from 'react';

import { type ResultType } from './SearchResultType';

import styles from './SearchResults.module.css';

function SearchResults({
    result,
    resultIndex,
    setResultIndex,
    optionClick,
}: {
    result: ResultType[] | null;
    resultIndex: number;
    setResultIndex: (index: number) => void;
    optionClick: (el: ResultType) => () => void;
}) {
    const categoryLabels = {
        objects: 'object',
        transactions: 'transaction',
        addresses: 'address',
    };

    if (!result) return <></>;

    if (result.length === 0)
        return (
            <div className={styles.results}>
                <p className={styles.noresults} role="alert">
                    {' '}
                    No Results{' '}
                </p>
            </div>
        );

    return (
        <div
            className={styles.results}
            id="SearchResults"
            aria-label="search results"
        >
            <div
                role="listbox"
                aria-activedescendant={`Option-${
                    categoryLabels[result[resultIndex].category]
                }`}
                tabIndex={0}
            >
                {result.map((el, index) => (
                    <Fragment key={index}>
                        <label
                            htmlFor={`Option-${categoryLabels[el.category]}`}
                        >
                            <span>{categoryLabels[el.category]}</span>
                            <span>{el.input}</span>
                        </label>
                        <input
                            id={`Option-${categoryLabels[el.category]}`}
                            type="radio"
                            role="option"
                            aria-selected={index === resultIndex}
                            checked={index === resultIndex}
                            className={
                                index === resultIndex
                                    ? styles.selectedoption
                                    : ''
                            }
                            onClick={optionClick(el)}
                        />
                    </Fragment>
                ))}
            </div>
        </div>
    );
}

export default SearchResults;
