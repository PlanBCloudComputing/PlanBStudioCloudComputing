# Forecast stress test (owner: Katie) — due Fri 13 Nov

Fill this in before writing the engine. Every team member must be able to explain it in one sentence.

**One-sentence explanation (write it first):**

we can test how robust each event plan is by creating multiple slightly altered versions of a saved weather forecast and calculating the percentage of simulations in which all activities remain within their weather tolerances.

## 1. What is perturbed

The precipitation probability, wind speed and timing of the saved weather forecast will be randomly adjusted. Temperature will remain unchanged in the initial version. Changing the timing allows us to account for weather conditions arriving earlier or later than originally forecast.

## 2. How much

Precipitation probability: add a normally distributed random value with a mean of 0 and a standard deviation of 15 percentage points. Restrict the resulting probability to between 0% and 100%.

Wind speed: multiply the original wind speed by a normally distributed random value with a mean of 1 and a standard deviation of 0.2. Restrict wind speeds to non-negative values.

Timing: randomly shift the forecast by −2, −1, 0, 1 or 2 hours, with each option equally likely. Use the nearest available forecast value at the boundaries.

## 3. Reproducibility

Each saved comparison will store the random seed, forecast snapshot ID, number of simulations and method version. Both plans will be tested against the same forecast variations to ensure a fair comparison. Using the same inputs, unchanged plans and implementation will allow the results to be reproduced.


## 4. Output

The endpoint will return the percentage of simulations in which all activities remain within their weather tolerances for each plan. It will also identify the weakest activity based on how frequently it exceeds its tolerances.

The results represent robustness under the chosen simulation assumptions rather than a probability of success.

## 5. Cost and scaling
Users will be able to select 500, 2,000 or 5,000 forecast variations. Each variation requires generating modified weather conditions and checking the tolerances of scheduled activities.

The proposed Cloud Run configuration is 1 vCPU with a concurrency of 1 for the scaling experiment. Increasing the number of simultaneous requests will allow us to investigate autoscaling under genuine computational demand. No artificial delays or unnecessary loops will be used.


## 6. Tests

The engine will be tested using small examples with known expected results.
- If a maximum wind tolerance is 30 km/h and the simulated wind speeds are 20, 30, 35 and 25 km/h, the expected robustness score is 75%.
- If all simulations exceed an activity's tolerance, the expected score is 0%.
- If all activities remain within their tolerances in every simulation, the expected score is 100%.
- Repeating a comparison with identical inputs and the same random seed should produce identical results.
