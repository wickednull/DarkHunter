# Contributing to DarkHunter

First off, thank you for considering contributing to DarkHunter! It's people like you that make DarkHunter such a great tool.

## Where do I go from here?

If you've noticed a bug or have a feature request, [make one](https://github.com/wickednull/DarkHunter/issues/new)! It's generally best if you get confirmation of your bug or approval for your feature request this way before starting to code.

### Fork & create a branch

If this is something you think you can fix, then [fork DarkHunter](https://github.com/wickednull/DarkHunter/fork) and create a branch with a descriptive name.

A good branch name would be (where issue #38 is the ticket you're working on):

```sh
git checkout -b 38-add-awesome-new-feature
```

### Get the test suite running

Make sure you're running with the latest version of the dependencies.

```sh
pip install -r requirements.txt
```

### Implement your fix or feature

At this point, you're ready to make your changes! Feel free to ask for help; everyone is a beginner at first 😸

### Make a Pull Request

At this point, you should switch back to your master branch and make sure it's up to date with DarkHunter's master branch:

```sh
git remote add upstream git@github.com:wickednull/DarkHunter.git
git checkout master
git pull upstream master
```

Then update your feature branch from your local copy of master, and push it!

```sh
git checkout 38-add-awesome-new-feature
git rebase master
git push --force-with-lease origin 38-add-awesome-new-feature
```

Finally, go to GitHub and [make a Pull Request](https://github.com/wickednull/DarkHunter/compare/master...38-add-awesome-new-feature)

### Keeping your Pull Request updated

If a maintainer asks you to "rebase" your PR, they're saying that a lot of code has changed, and that you need to update your branch so it's easier to merge.

To learn more about rebasing and merging, check out this guide on [merging vs. rebasing](https://www.atlassian.com/git/tutorials/merging-vs-rebasing).

## Guideline for bug reports

**Please, don't open an issue for a security vulnerability.**

Security issues should be reported privately to [INSERT CONTACT METHOD].

## Guideline for feature requests

If you have an idea for a new feature, please open an issue and describe what you would like to see.
