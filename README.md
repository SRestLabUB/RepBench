# Representation Matters: An Empirical Study of Static-Analysis-Based Code Representations for LLM Vulnerability Reasoning

# Problem Statement
Automatic vulnerability detection has seen many developments over the past decade with static application testing, deep learning systems, and most recently with the prevalence of large language models (LLMs) within automated program repair (APR) systems. A common challenge among all approaches is representing vulnerability semantics and program characteristics (e.g. control-flow diagram, data-flow diagram, etc) without a domain expert intervening. Even with expert-level human intervention there are many difficulties. We aim to analyze and perform empirical testing of various program analysis approaches through the prompting of a LLM-based APR system in order to evaluate the efficacy of the various software analysis approaches within APR on a few well known vulnerabilities (code samples provided through CWEs test suite).

# Existing Approaches & How Project Complements Them How others use Program Analysis in LLM-based APR systems

[1] Xin Zhou, Sicong Cao, Xiaobing Sun, and David Lo. Large language model for vulnerability detection and repair: Literature review and the road ahead. ACM 2024

[1] is a survey paper that has a section about various program analysis approaches for LLM APR. We used this paper to learn about other related work pertaining to how program analysis is used in LLM APR systems. Figure 1 in this paper gives a nice overview of the survey.

[2] Peng, T., Chen, S., Zhu, F., Tang, J., Liu, J., and Hu, X. Ptlvd:program slicing and transformer-based line-level vulnerability detection system. In 23rd IEEE International Working Conference on Source Code Analysis and Manipulation, SCAM 2023, Bogotá, Colombia, October 2-3, 2023 (2023), L. Moonen, C. D. Newman, and A. Gorla, Eds., IEEE, pp. 162–173.

[2] Includes a deep learning approach that uses program slices that are called “Code Gadgets". We could possibly add this to our list of analysis methods to evaluate.

[3] Wang, H., Tang, Z., Tan, S. H., Wang, J., Liu, Y., Fang, H., Xia, C., and Wang, Z. Combining structured static code information and dynamic symbolic traces for software vulnerability prediction. In Proceedings of the 46th International Conference on Software Engineering (2024), ACM. 

[3] If we are to include dynamic analysis information in our empirical study then this paper does discuss some combined dynamic and static information approaches. However this is an approach for deep learning models.

[4] Zhang, J., Liu, Z., Hu, X., Xia, X., and Li, S. Vulnerability detection by learning from syntax-based execution paths of code. IEEE Trans. Software Eng. 49, 8 (2023), 4196–4212.

[4] Discusses a new type of control flow graph (CFG) called a Syntax-Based Control Flow Graph. This CFG is stated to be similar to CFGs produced by Joern however they mention that Joern uses finer-grained ASTs for CFG generation.

[5] Nong, Y., et al. {APPATCH}: Automated adaptive prompting large language models
for {Real-World} software vulnerability patching. USENIX Security 2025.

[5] System dependence graphs (SDGs) are mentioned in the paper from the course reading list. We could include those in our analysis. Could use the same method (interprocedural dependence analysis) to generate the SGDs for our purpose. Linked paper for SDGs (Interprocedural Slicing Using DependenceGraphs) has more insight into generation also.

[6] Mirsky, Y. et al. {VulChecker}: Graph-based vulnerability localization in source
code. USENIX Security 2023.

[6] Course reading list paper that proposes an enriched version of program dependency graphs called ePDGs. These ePDGs are used with the deep learning model VulChecker but we could use the ePDGs in our analysis.

Empirical Studies on program analysis techniques used in LLM-based APR systems

[7] Qijia Chen, Dongcheng Li, Man Zhao*, W. Eric Wong, and Hui Li. Learning-Based Automated Program Repair: A Systematic Literature Review. IEEE 2025

[7] Gives an overview of empirical studies that have been performed on APR systems. This paper is where [4] was found which seems closely related to our goals.

[8] M.  Namavar,  N.  Nashid,  and  A.  Mesbah, A  controlled experiment of different code representations for learning based program repair, Empir. Softw. Eng., vol. 27, no. 7, p.
190, 2022.

[8] is related to our goal in the sense that we want to test different program analysis representations against LLM-based APR systems. This paper uses existing program representations (text, ASTs) and introduces some new representations and then evaluates the performance of those approaches. Our paper would build off of this and use it with prevalent LLM-based APR systems.
# High Level Description of Software Analysis Approach
We plan to use primarily static software analysis approaches (e.g. Abstract Syntax Trees (AST), Control Flow Graphs, Data Dependency Graphs, Program Dependency Graphs, Code Dependency Graphs, and more) for empirical testing within an automatic program repair system. We plan to use existing tools such as Joern to generate the structured data. There are also program analysis approaches presented through papers (more in “Related Works” section) that we wish to evaluate.

We would like to also include dynamic analysis and AI-assisted analysis techniques however we feel that it may be out of scope for the semester time constraint.
# Research Questions

- How do various program analysis approaches for LLM-based automated program repair systems perform against current LLM models?
- How does combining program analysis approaches in LLM APR systems affect performance?
- After some analysis, can we slice up and combine various program analysis tools to improve current LLM APR performance. (might be out of scope)
- What is the trade-off between representation complexity (token overhead) and detection performance across different software analysis structures?

# Initial Plan (expected artifacts and evaluation plan)
## High Level Overview of Plan:
1. Decide on a specific subset of Common Weakness Enumerations to test (e.g. integer overflow, buffer overflow, etc). To ensure a rigorous evaluation, we will utilize established academic benchmark datasets, such as the NIST Juliet C/C++ Test Suite.
2. Decide which software-analysis based inputs we want to provide to the APR LLM (e.g. AST, control flow, data flow, PDG, CDG, more)
3. Find required tools to generate the structured data from the program analysis approaches (e.g. Joern).
4. Decide on a static APR LLM approach, such as using chain-of-thought prompt engineering but we swap out the different "Structure-Aware" inputs for testing.
5. Test and analyze performance of different approaches from step 2
6. (Optional) Test across older LLM models along with latest

## How we Evaluate Performance:
- Vulnerability Detection Accuracy: It will measure the precision, recall, and overall accuracy of the LLM in correctly identifying the location, and type of the vulnerability. This directly answers our research question by measuring which input provides the clearest and most actionable context for the LLM to recognize a specific vulnerability without human expert intervention.
- Representation Efficiency. It will measure the ratio of token count required to represent each software analysis structure relative to its detection accuracy. We will analyze the trade-offs to determine if highly condensed and semantic structures yield better detection performance with fewer tokens compared to verbose structures.

## Expected Artifacts:
- Performance (Accuracy) results of vulnerability detection across various software analysis approaches and across multiple models
- Code to represent chosen vulnerabilities to test
- Code to generate software-analysis structures (AST, control flow diagrams, etc) from vulnerable programs.
-Input prompts for LLM-based APRs augmented with software-analysis structures

# Division of Labor
## Referencing our high level overview of the plan
1. Decide on a specific subset of Common Weakness Enumerations to test (e.g. integer overflow, buffer overflow, etc). To ensure a rigorous evaluation, we will utilize established academic benchmark datasets, such as the NIST Juliet C/C++ Test Suite. **- Johnathan Tang**
2. Decide which software-analysis based inputs we want to provide to the APR LLM (e.g. AST, control flow, data flow, PDG, CDG, more) **- Both**
3. Find required tools to generate the structured data from the program analysis approaches (e.g. Joern). **- Jonathan Tang**
4. Decide on a static APR LLM approach, such as using chain-of-thought prompt engineering but we swap out the different "Structure-Aware" inputs for testing. **- Andrew Stoltman**
5. Test and analyze performance of different approaches from step 2 **- Both**
6. (Optional) Test across older LLM models along with latest **- Andrew Stoltman**
## For sections with “Both”
2. The software analysis approaches can be split between both team members. Each member will research how to generate the structure data from the CWEs with existing tools (e.g. Joren).
5. Metrics and visualizations provided through evaluation can be split upon team members.
